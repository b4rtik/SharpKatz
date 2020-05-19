using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpKatz
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

        public struct WIN_VER_INFO
        {
            public string chOSMajorMinor;
            public long dwBuildNumber;
            public UNICODE_STRING ProcName;
            public IntPtr hTargetPID;
            public string lpApiCall;
            public int SystemCall;
        }

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
            public UInt32 LowPart;
            public UInt32 HighPart;
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

        public enum PSS_CAPTURE_FLAGS
        {
            PSS_CAPTURE_NONE,
            PSS_CAPTURE_VA_CLONE,
            PSS_CAPTURE_RESERVED_00000002,
            PSS_CAPTURE_HANDLES,
            PSS_CAPTURE_HANDLE_NAME_INFORMATION,
            PSS_CAPTURE_HANDLE_BASIC_INFORMATION,
            PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION,
            PSS_CAPTURE_HANDLE_TRACE,
            PSS_CAPTURE_THREADS,
            PSS_CAPTURE_THREAD_CONTEXT,
            PSS_CAPTURE_THREAD_CONTEXT_EXTENDED,
            PSS_CAPTURE_RESERVED_00000400,
            PSS_CAPTURE_VA_SPACE,
            PSS_CAPTURE_VA_SPACE_SECTION_INFORMATION,
            PSS_CAPTURE_IPT_TRACE,
            PSS_CREATE_BREAKAWAY_OPTIONAL,
            PSS_CREATE_BREAKAWAY,
            PSS_CREATE_FORCE_BREAKAWAY,
            PSS_CREATE_USE_VM_ALLOCATIONS,
            PSS_CREATE_MEASURE_PERFORMANCE,
            PSS_CREATE_RELEASE_SECTION
        }

        public enum MINIDUMP_CALLBACK_TYPE : uint
        {
            ModuleCallback,
            ThreadCallback,
            ThreadExCallback,
            IncludeThreadCallback,
            IncludeModuleCallback,
            MemoryCallback,
            CancelCallback,
            WriteKernelMinidumpCallback,
            KernelMinidumpStatusCallback,
            RemoveMemoryCallback,
            IncludeVmRegionCallback,
            IoStartCallback,
            IoWriteAllCallback,
            IoFinishCallback,
            ReadMemoryFailureCallback,
            SecondaryFlagsCallback,
            IsProcessSnapshotCallback,
            VmStartCallback,
            VmQueryCallback,
            VmPreReadCallback,
            VmPostReadCallback
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public unsafe struct MINIDUMP_THREAD_CALLBACK
        {
            public uint ThreadId;
            public IntPtr ThreadHandle;
            public fixed byte Context[1232];
            public uint SizeOfContext;
            public ulong StackBase;
            public ulong StackEnd;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_THREAD_EX_CALLBACK
        {
            public MINIDUMP_THREAD_CALLBACK BasePart;
            public ulong BackingStoreBase;
            public ulong BackingStoreEnd;
        }

        enum VS_FIXEDFILEINFO_FileFlags : uint
        {
            VS_FF_DEBUG = 0x00000001,
            VS_FF_INFOINFERRED = 0x00000010,
            VS_FF_PATCHED = 0x00000004,
            VS_FF_PRERELEASE = 0x00000002,
            VS_FF_PRIVATEBUILD = 0x00000008,
            VS_FF_SPECIALBUILD = 0x00000020
        }

        enum VS_FIXEDFILEINFO_FileOSFlags : uint
        {
            VOS_DOS = 0x00010000,
            VOS_NT = 0x00040000,
            VOS__WINDOWS16 = 0x00000001,
            VOS__WINDOWS32 = 0x00000004,
            VOS_OS216 = 0x00020000,
            VOS_OS232 = 0x00030000,
            VOS__PM16 = 0x00000002,
            VOS__PM32 = 0x00000003,
            VOS_UNKNOWN = 0x00000000
        }

        enum VS_FIXEDFILEINFO_FileTypeFlags : uint
        {
            VFT_APP = 0x00000001,
            VFT_DLL = 0x00000002,
            VFT_DRV = 0x00000003,
            VFT_FONT = 0x00000004,
            VFT_STATIC_LIB = 0x00000007,
            VFT_UNKNOWN = 0x00000000,
            VFT_VXD = 0x00000005
        }

        enum VS_FIXEFILEINFO_FileSubTypeFlags : uint
        {
            // If the FileType is VFT_DRV
            VFT2_DRV_COMM = 0x0000000A,
            VFT2_DRV_DISPLAY = 0x00000004,
            VFT2_DRV_INSTALLABLE = 0x00000008,
            VFT2_DRV_KEYBOARD = 0x00000002,
            VFT2_DRV_LANGUAGE = 0x00000003,
            VFT2_DRV_MOUSE = 0x00000005,
            VFT2_DRV_NETWORK = 0x00000006,
            VFT2_DRV_PRINTER = 0x00000001,
            VFT2_DRV_SOUND = 0x00000009,
            VFT2_DRV_SYSTEM = 0x00000007,
            VFT2_DRV_VERSIONED_PRINTER = 0x0000000C,

            // If the FileType is VFT_FONT
            VFT2_FONT_RASTER = 0x00000001,
            VFT2_FONT_TRUETYPE = 0x00000003,
            VFT2_FONT_VECTOR = 0x00000002,

            VFT2_UNKNOWN = 0x00000000
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct VS_FIXEDFILEINFO
        {
            public uint dwSignature;
            public uint dwStrucVersion;
            public uint dwFileVersionMS;
            public uint dwFileVersionLS;
            public uint dwProductVersionMS;
            public uint dwProductVersionLS;
            public uint dwFileFlagsMask;
            public uint dwFileFlags;
            public uint dwFileOS;
            public uint dwFileType;
            public uint dwFileSubtype;
            public uint dwFileDateMS;
            public uint dwFileDateLS;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_MODULE_CALLBACK
        {
            public IntPtr FullPath; // This is a PCWSTR
            public ulong BaseOfImage;
            public uint SizeOfImage;
            public uint CheckSum;
            public uint TimeDateStamp;
            public VS_FIXEDFILEINFO VersionInfo;
            public IntPtr CvRecord;
            public uint SizeOfCvRecord;
            public IntPtr MiscRecord;
            public uint SizeOfMiscRecord;
        }

        public struct MINIDUMP_INCLUDE_THREAD_CALLBACK
        {
            public uint ThreadId;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_INCLUDE_MODULE_CALLBACK
        {
            public ulong BaseOfImage;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_IO_CALLBACK
        {
            public IntPtr Handle;
            public ulong Offset;
            public IntPtr Buffer;
            public uint BufferBytes;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_READ_MEMORY_FAILURE_CALLBACK
        {
            public ulong Offset;
            public uint Bytes;
            public int FailureStatus; // HRESULT
        }

        [Flags]
        public enum MINIDUMP_SECONDARY_FLAGS : uint
        {
            MiniSecondaryWithoutPowerInfo = 0x00000001
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct MINIDUMP_CALLBACK_INPUT
        {

            const int CallbackTypeOffset = 4 + 8;

            const int UnionOffset = CallbackTypeOffset + 4;

            [FieldOffset(0)]
            public uint ProcessId;
            [FieldOffset(4)]
            public IntPtr ProcessHandle;
            [FieldOffset(CallbackTypeOffset)]
            public MINIDUMP_CALLBACK_TYPE CallbackType;

            [FieldOffset(UnionOffset)]
            public int Status; // HRESULT
            [FieldOffset(UnionOffset)]
            public MINIDUMP_THREAD_CALLBACK Thread;
            [FieldOffset(UnionOffset)]
            public MINIDUMP_THREAD_EX_CALLBACK ThreadEx;
            [FieldOffset(UnionOffset)]
            public MINIDUMP_MODULE_CALLBACK Module;
            [FieldOffset(UnionOffset)]
            public MINIDUMP_INCLUDE_THREAD_CALLBACK IncludeThread;
            [FieldOffset(UnionOffset)]
            public MINIDUMP_INCLUDE_MODULE_CALLBACK IncludeModule;
            [FieldOffset(UnionOffset)]
            public MINIDUMP_IO_CALLBACK Io;
            [FieldOffset(UnionOffset)]
            public MINIDUMP_READ_MEMORY_FAILURE_CALLBACK ReadMemoryFailure;
            [FieldOffset(UnionOffset)]
            public MINIDUMP_SECONDARY_FLAGS SecondaryFlags;
        }

        public enum STATE : uint
        {
            MEM_COMMIT = 0x1000,
            MEM_FREE = 0x10000,
            MEM_RESERVE = 0x2000
        }

        public enum TYPE : uint
        {
            MEM_IMAGE = 0x1000000,
            MEM_MAPPED = 0x40000,
            MEM_PRIVATE = 0x20000
        }

        [Flags]
        public enum PROTECT : uint
        {
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_TARGETS_INVALID = 0x40000000,
            PAGE_TARGETS_NO_UPDATE = 0x40000000,

            PAGE_GUARD = 0x100,
            PAGE_NOCACHE = 0x200,
            PAGE_WRITECOMBINE = 0x400
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_MEMORY_INFO
        {
            public ulong BaseAddress;
            public ulong AllocationBase;
            public uint AllocationProtect;
            public uint __alignment1;
            public ulong RegionSize;
            public STATE State;
            public PROTECT Protect;
            public TYPE Type;
            public uint __alignment2;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MemoryCallbackOutput
        {
            public ulong MemoryBase;
            public uint MemorySize;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct CancelCallbackOutput
        {
            [MarshalAs(UnmanagedType.Bool)]
            public bool CheckCancel;
            [MarshalAs(UnmanagedType.Bool)]
            public bool Cancel;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MemoryInfoCallbackOutput
        {
            public MINIDUMP_MEMORY_INFO VmRegion;
            [MarshalAs(UnmanagedType.Bool)]
            public bool Continue;
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

        [StructLayout(LayoutKind.Explicit, Pack = 4)]
        public struct MINIDUMP_CALLBACK_OUTPUT
        {
            [FieldOffset(0)]
            public MODULE_WRITE_FLAGS ModuleWriteFlags;
            [FieldOffset(0)]
            public THREAD_WRITE_FLAGS ThreadWriteFlags;
            [FieldOffset(0)]
            public uint SecondaryFlags;
            [FieldOffset(0)]
            public MemoryCallbackOutput Memory;
            [FieldOffset(0)]
            public CancelCallbackOutput Cancel;
            [FieldOffset(0)]
            public IntPtr Handle;
            [FieldOffset(0)]
            public MemoryInfoCallbackOutput MemoryInfo;
            [FieldOffset(0)]
            public int Status; // HRESULT
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool MINIDUMP_CALLBACK_ROUTINE(
            [In] IntPtr CallbackParam,
            [In] ref MINIDUMP_CALLBACK_INPUT CallbackInput,
            [In, Out] ref MINIDUMP_CALLBACK_OUTPUT CallbackOutput
            );

        public struct MINIDUMP_CALLBACK_INFORMATION
        {
            public MINIDUMP_CALLBACK_ROUTINE CallbackRoutine;
            public IntPtr CallbackParam;
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


        public static int NtFilterToken(IntPtr TokenHandle, uint Flags, IntPtr SidsToDisable, IntPtr PrivilegesToDelete, IntPtr RestrictedSids, ref IntPtr hToken)
        {
            IntPtr proc = GetProcAddress(GetNtDll(), "NtFilterToken");
            SysCall.Delegates.NtFilterToken NtSetInformationToken = (SysCall.Delegates.NtFilterToken)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.NtFilterToken));
            return NtFilterToken(TokenHandle, Flags, SidsToDisable, PrivilegesToDelete, RestrictedSids, ref hToken);
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

        private static IntPtr GetDbgcore()
        {

            return LoadLibrary("dbgcore.dll");

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

        public static bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint newprotect, out uint oldprotect)
        {
            IntPtr proc = GetProcAddress(GetKernelbase(), "VirtualProtectEx");
            SysCall.Delegates.VirtualProtectEx VirtualProtectEx = (SysCall.Delegates.VirtualProtectEx)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.VirtualProtectEx));
            return VirtualProtectEx(hProcess, lpAddress, dwSize, newprotect, out oldprotect);
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

        public static bool MiniDumpWriteDump(IntPtr hProcess, uint ProcessId, Microsoft.Win32.SafeHandles.SafeFileHandle hFile, int DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam)
        {
            IntPtr proc = GetProcAddress(GetDbgcore(), "MiniDumpWriteDump");
            SysCall.Delegates.MiniDumpWriteDump MiniDumpWriteDump = (SysCall.Delegates.MiniDumpWriteDump)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.MiniDumpWriteDump));
            return MiniDumpWriteDump(hProcess, ProcessId, hFile, DumpType, ExceptionParam, UserStreamParam, CallbackParam);
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

        public static int PssCaptureSnapshot(IntPtr ProcessHandle, PSS_CAPTURE_FLAGS CaptureFlags, int ThreadContextFlags, ref IntPtr SnapshotHandle)
        {
            IntPtr proc = GetProcAddress(GetKernel32(), "PssCaptureSnapshot");
            SysCall.Delegates.PssCaptureSnapshot PssCaptureSnapshot = (SysCall.Delegates.PssCaptureSnapshot)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.PssCaptureSnapshot));
            return PssCaptureSnapshot(ProcessHandle, CaptureFlags, ThreadContextFlags, ref SnapshotHandle);
        }

        public static bool ConvertSidToStringSid(byte[] pSID, out string ptrSid)
        {
            IntPtr proc = GetProcAddress(GetAdvapi32(), "ConvertSidToStringSidA");
            SysCall.Delegates.ConvertSidToStringSid ConvertSidToStringSid = (SysCall.Delegates.ConvertSidToStringSid)Marshal.GetDelegateForFunctionPointer(proc, typeof(SysCall.Delegates.ConvertSidToStringSid));
            return ConvertSidToStringSid(pSID, out ptrSid);
        }

        public static IntPtr GetProcAddress(IntPtr hModule, string procName)
        {
            return CustomLoadLibrary.GetExportAddress(hModule, procName);
        }

        public static IntPtr LoadLibrary(string name)
        {
            return CustomLoadLibrary.GetDllAddress(name, true);
        }
    }
}
