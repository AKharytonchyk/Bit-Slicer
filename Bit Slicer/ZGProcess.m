/*
 * Copyright (c) 2012 Mayur Pawashe
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * Neither the name of the project's author nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#import "ZGProcess.h"
#import "ZGMachBinary.h"
#import "ZGVirtualMemory.h"
#import "ZGMachBinary.h"
#import "ZGMachBinaryInfo.h"
#import "ZGPrivateCoreSymbolicator.h"
#import <mach-o/loader.h>
#import <mach-o/fat.h>
#import <libkern/OSByteOrder.h>

@implementation ZGProcess
{
	NSMutableDictionary<NSString *, NSMutableDictionary *> * _Nullable _cacheDictionary;
	
	ZGMachBinary * _Nullable _mainMachBinary;
	ZGMachBinary * _Nullable _dylinkerBinary;
	
	id <ZGSymbolicator> _Nullable _symbolicator;
	BOOL _failedCreatingSymbolicator;
	dispatch_queue_t _symbolicatorQueue;
}

- (instancetype)initWithName:(NSString *)processName internalName:(NSString *)internalName processID:(pid_t)aProcessID type:(ZGProcessType)processType translated:(BOOL)translated
{
	if ((self = [super init]))
	{
		_name = [processName copy];
		_internalName = [internalName copy];
		_processID = aProcessID;
		_type = processType;
		_translated = translated;
		_symbolicatorQueue = dispatch_queue_create(NULL, DISPATCH_QUEUE_SERIAL);
	}
	
	return self;
}

- (instancetype)initWithName:(NSString *)processName internalName:(NSString *)internalName type:(ZGProcessType)processType translated:(BOOL)translated
{
	return [self initWithName:processName internalName:internalName processID:NON_EXISTENT_PID_NUMBER type:processType translated:translated];
}

- (instancetype)initWithProcess:(ZGProcess *)process processTask:(ZGMemoryMap)processTask name:(NSString *)name
{
	self = [self initWithName:name internalName:process.internalName processID:process.processID type:process.type translated:process.translated];
	if (self != nil)
	{
		_processTask = processTask;
	}
	return self;
}

- (instancetype)initWithProcess:(ZGProcess *)process
{
	return [self initWithProcess:process processTask:process.processTask name:process.name];
}

- (instancetype)initWithProcess:(ZGProcess *)process name:(NSString *)name
{
	return [self initWithProcess:process processTask:process.processTask name:name];
}

- (instancetype)initWithProcess:(ZGProcess *)process processTask:(ZGMemoryMap)processTask
{
	return [self initWithProcess:process processTask:processTask name:process.name];
}

- (void)dealloc
{
	if ([self valid] && _symbolicator != nil)
	{
		[_symbolicator invalidate];
	}
}

- (BOOL)isEqual:(id)process
{
	return ([(ZGProcess *)process processID] == _processID);
}

- (NSUInteger)hash
{
	return (NSUInteger)_processID;
}

- (BOOL)valid
{
	return _processID != NON_EXISTENT_PID_NUMBER;
}

- (id<ZGSymbolicator>)symbolicator
{
	__block id<ZGSymbolicator> symbolicator = nil;
	
	dispatch_sync(_symbolicatorQueue, ^{
		if ([self valid] && _symbolicator == nil && !_failedCreatingSymbolicator)
		{
			symbolicator = [[ZGPrivateCoreSymbolicator alloc] initWithTask:_processTask];
			// Creating the symbolicator can be very costly; make sure we don't try creating one often if it keeps failing
			if (symbolicator == nil)
			{
				_failedCreatingSymbolicator = YES;
			}
			
			_symbolicator = symbolicator;
		}
		else
		{
			symbolicator = _symbolicator;
		}
	});
	
	return symbolicator;
}

- (NSMutableDictionary<NSString *, NSMutableDictionary *> *)cacheDictionary
{
	if (_cacheDictionary == nil)
	{
		_cacheDictionary = [[NSMutableDictionary alloc] initWithDictionary:@{ZGMachBinaryPathToBinaryInfoDictionary : [NSMutableDictionary dictionary], ZGMachBinaryPathToBinaryDictionary : [NSMutableDictionary dictionary]}];
	}
	return (id _Nonnull)_cacheDictionary;
}

- (ZGMachBinary *)dylinkerBinary
{
	if (_dylinkerBinary == nil)
	{
		_dylinkerBinary = [ZGMachBinary dynamicLinkerMachBinaryInProcess:self];
	}
	return _dylinkerBinary;
}

- (ZGMachBinary *)mainMachBinary
{
	if (_mainMachBinary == nil)
	{
		_mainMachBinary = [ZGMachBinary mainMachBinaryFromMachBinaries:[ZGMachBinary machBinariesInProcess:self]];
	}
	return _mainMachBinary;
}

- (BOOL)hasGrantedAccess
{
    return MACH_PORT_VALID(_processTask);
}

+ (uint32_t)platformInMachHeaderBytes:(const uint8_t *)bytes length:(size_t)length
{
	if (length < sizeof(struct mach_header))
	{
		return 0;
	}

	uint32_t magic = *(const uint32_t *)bytes;
	if (magic != MH_MAGIC && magic != MH_CIGAM && magic != MH_MAGIC_64 && magic != MH_CIGAM_64)
	{
		return 0;
	}

	BOOL is64Bit = (magic == MH_MAGIC_64 || magic == MH_CIGAM_64);
	BOOL swapped = (magic == MH_CIGAM || magic == MH_CIGAM_64);

	uint32_t commandCount;
	size_t commandOffset;
	if (is64Bit)
	{
		if (length < sizeof(struct mach_header_64))
		{
			return 0;
		}
		const struct mach_header_64 *header = (const struct mach_header_64 *)bytes;
		commandCount = swapped ? OSSwapInt32(header->ncmds) : header->ncmds;
		commandOffset = sizeof(struct mach_header_64);
	}
	else
	{
		const struct mach_header *header = (const struct mach_header *)bytes;
		commandCount = swapped ? OSSwapInt32(header->ncmds) : header->ncmds;
		commandOffset = sizeof(struct mach_header);
	}

	for (uint32_t commandIndex = 0; commandIndex < commandCount; commandIndex++)
	{
		if (commandOffset + sizeof(struct load_command) > length)
		{
			break;
		}

		const struct load_command *loadCommand = (const struct load_command *)(bytes + commandOffset);
		uint32_t command = swapped ? OSSwapInt32(loadCommand->cmd) : loadCommand->cmd;
		uint32_t commandSize = swapped ? OSSwapInt32(loadCommand->cmdsize) : loadCommand->cmdsize;
		if (commandSize < sizeof(struct load_command) || commandOffset + commandSize > length)
		{
			break;
		}

		if (command == LC_BUILD_VERSION && commandOffset + sizeof(struct build_version_command) <= length)
		{
			const struct build_version_command *buildVersion = (const struct build_version_command *)(bytes + commandOffset);
			return swapped ? OSSwapInt32(buildVersion->platform) : buildVersion->platform;
		}
		if (command == LC_VERSION_MIN_IPHONEOS)
		{
			return PLATFORM_IOS;
		}
		if (command == LC_VERSION_MIN_MACOSX)
		{
			return PLATFORM_MACOS;
		}

		commandOffset += commandSize;
	}

	return 0;
}

+ (uint32_t)executablePlatformAtPath:(NSString *)executablePath
{
	NSData *fileData = [NSData dataWithContentsOfFile:executablePath options:NSDataReadingMappedIfSafe error:NULL];
	if (fileData == nil)
	{
		return 0;
	}

	const uint8_t *bytes = fileData.bytes;
	size_t length = fileData.length;
	if (length < sizeof(uint32_t))
	{
		return 0;
	}

	uint32_t magic = *(const uint32_t *)bytes;
	if (magic != FAT_MAGIC && magic != FAT_CIGAM && magic != FAT_MAGIC_64 && magic != FAT_CIGAM_64)
	{
		// Thin Mach-O
		return [self platformInMachHeaderBytes:bytes length:length];
	}

	// Universal binary: fat headers are stored big-endian on disk
	if (length < sizeof(struct fat_header))
	{
		return 0;
	}

	BOOL is64Bit = (magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64);
	const struct fat_header *fatHeader = (const struct fat_header *)bytes;
	uint32_t architectureCount = OSSwapBigToHostInt32(fatHeader->nfat_arch);
	size_t architectureOffset = sizeof(struct fat_header);

	for (uint32_t architectureIndex = 0; architectureIndex < architectureCount; architectureIndex++)
	{
		uint64_t sliceOffset;
		uint64_t sliceSize;
		if (is64Bit)
		{
			if (architectureOffset + sizeof(struct fat_arch_64) > length)
			{
				break;
			}
			const struct fat_arch_64 *architecture = (const struct fat_arch_64 *)(bytes + architectureOffset);
			sliceOffset = OSSwapBigToHostInt64(architecture->offset);
			sliceSize = OSSwapBigToHostInt64(architecture->size);
			architectureOffset += sizeof(struct fat_arch_64);
		}
		else
		{
			if (architectureOffset + sizeof(struct fat_arch) > length)
			{
				break;
			}
			const struct fat_arch *architecture = (const struct fat_arch *)(bytes + architectureOffset);
			sliceOffset = OSSwapBigToHostInt32(architecture->offset);
			sliceSize = OSSwapBigToHostInt32(architecture->size);
			architectureOffset += sizeof(struct fat_arch);
		}

		if (sliceOffset > length || sliceSize > length - sliceOffset)
		{
			continue;
		}

		uint32_t platform = [self platformInMachHeaderBytes:(bytes + sliceOffset) length:(size_t)sliceSize];
		if (platform != 0)
		{
			return platform;
		}
	}

	return 0;
}

- (ZGMemorySize)pointerSize
{
	return ZG_PROCESS_POINTER_SIZE(_type);
}

@end
