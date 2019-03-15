using System;
using System.IO;
using System.Text.RegularExpressions;

namespace Microsoft.VssAdmin 
{
    public enum VssWriterState
    {
        Unknown = 0,             Stable, 
        WaitingForFreeze,        WaitingForThaw, 
        WaitingForPostSnapshot,  WaitingForBackupComplete, 
        FailedAtIdentify,        FailedAtPrepareBackup, 
        FailedAtPrepareSnapshot, FailedAtFreeze,
        FailedAtThaw,            FailedAtPostSnapshot,
        FailedAtBackupComplete,  FailedAtPreRestore,
        FailedAtPostRestore,     FailedAtBackupShutdown
    }

    public class VssWriter
    {
        public readonly string Name;
        public readonly Guid Id;
        public readonly Guid InstanceId;
        public readonly VssWriterState State;
        public readonly string LastError;

        public VssWriter(string name, Guid id, Guid instanceId, VssWriterState state, string lastError)
        {
            Name = name;
            Id = id;
            InstanceId = instanceId;
            State = state;
            LastError = lastError;
        }
    }

    public enum VssProviderType
    {
        Unknown = 0,
        System,
        Software,
        Hardware,
        FileShare
    }

    public class VssProvider 
    {
        public readonly string Name;
        public readonly VssProviderType ProviderType;
        public readonly Guid Id;
        public readonly Version Version;

        public VssProvider(string name, VssProviderType providerType, Guid id, Version version)
        {
            Name = name;
            ProviderType = providerType;
            Id = id;
            Version = version;
        }
    }

    public class VssVolume
    {
        public readonly string Path;
        public readonly string Name;

        public VssVolume(string path, string name)
        {
            Path = path;
            Name = name;
        }
    }

    public struct VssStorageUsage
    {
        public readonly string Volume;
        public readonly long Bytes;
        public readonly double Percentage;

        public VssStorageUsage(DriveInfo drive, long bytes)
            :this()
        {
            Volume = drive.Name;
            Bytes  = bytes;
            Percentage = bytes == -1 ? 1 : ((double) bytes) / drive.TotalSize;
        }
    }

    public class VssShadowStorage
    {
        public readonly string ForVolume;
        public readonly string StorageVolume;
        public readonly VssStorageUsage UsedStorageSpace;
        public readonly VssStorageUsage AllocatedStorageSpace;
        public readonly VssStorageUsage MaximumStorageSpace;

        public VssShadowStorage(string forVolume, string storageVolume, VssStorageUsage usedSpace, VssStorageUsage allocatedSpace, VssStorageUsage maxSpace)
        {
            ForVolume = forVolume;
            StorageVolume = storageVolume;
            UsedStorageSpace = usedSpace;
            AllocatedStorageSpace = allocatedSpace;
            MaximumStorageSpace = maxSpace;
        }

        public static VssShadowStorage FromMatches(params Match[] matches)
        {
            if (matches.Length != 5)
                throw new ArgumentOutOfRangeException("Value must contain exactly 5 elements.", "matches");

            string storageVol = matches[1].Value.TrimEnd();

            return new VssShadowStorage(
                matches[0].Value.TrimEnd(),
                storageVol,
                ParseStorageValue(storageVol, matches[2].Value.TrimEnd()),
                ParseStorageValue(storageVol, matches[3].Value.TrimEnd()),
                ParseStorageValue(storageVol, matches[4].Value.TrimEnd()));
        }

        private static VssStorageUsage ParseStorageValue(string volume, string value)
        {
            Match volMatch = Regex.Match(volume, @"\w:(?=\)\\\\\?)");

            if (!volMatch.Success)
                throw new ArgumentException("Unrecognized volume: " + volume);

            DriveInfo driveInfo = GetDriveInfo(volMatch.Value);
            Match storageMatch = Regex.Match(value, @"(UNBOUNDED|\d{0,}\.{0,}\d{1,}\s\w{1,}(?=\s\())");

            if (!storageMatch.Success)
                throw new ArgumentException("Unrecognized value: " + value);

            if (storageMatch.Value == "UNBOUNDED")
                return new VssStorageUsage(driveInfo, -1);

            string[] split = storageMatch.Value.Split();

            switch(split[1])
            {
                case "B":
                case "Bytes":
                case "bytes":
                    return new VssStorageUsage(driveInfo, long.Parse(split[0]));
                case "KB":                        
                    return new VssStorageUsage(driveInfo, (long)(double.Parse(split[0]) * 1024));
                case "MB":                        
                    return new VssStorageUsage(driveInfo, (long)(double.Parse(split[0]) * 1048576));
                case "GB":                        
                    return new VssStorageUsage(driveInfo, (long)(double.Parse(split[0]) * 1073741824));
                default:
                    throw new ArgumentException("Unrecognized value: " + storageMatch.Value);
            }
        }

        private static DriveInfo GetDriveInfo(string volume)
        {
            foreach(DriveInfo drive in DriveInfo.GetDrives())
                if (drive.Name.StartsWith(volume, StringComparison.CurrentCultureIgnoreCase))
                    return drive;

            throw new ArgumentException("The drive " + volume + " was not found.");
        }
    }

    public enum VssSnapshotContext
    {
        Backup,
        FileShareBackup,
        NasRollback,
        AppRollback,
        ClientAccessible,
        ClientAccessibleWriters,
        All
    }
    
    public enum VssShadowcopyAttributes
    {
        Persistent,          NoAutoRecovery,
        ClientAccessible,    NoAutoRelease,
        NoWriters,           Transportable,
        NotSurfaced,         NotTransacted,
        HardwareAssisted,    Differential,
        Plex,                Imported,
        ExposedLocally,      ExposedRemotely,
        AutoRecovered,         RollbackRecovery,
        DelayedPostSnapshot, TxfRecovery,
        FileShare
    }

    public class VssShadowCopy
    {
        public readonly Guid SetId;
        public readonly DateTime CreationTime;
        public readonly Guid ShadowCopyId;
        public readonly string OriginalVolume;
        public readonly string ShadowCopyVolume;
        public readonly string OriginatingMachine;
        public readonly string ServiceMachine;
        public readonly VssProvider Provider;
        public readonly VssSnapshotContext Context;
        public readonly VssShadowcopyAttributes[] Attributes;

        public VssShadowCopy(
            Guid setId,                 DateTime creationTime, 
            Guid id,                    string forVol, 
            string shadowCopyVol,       string originatingMachine, 
            string serviceMachine,      VssProvider provider, 
            VssSnapshotContext context, VssShadowcopyAttributes[] attributes)
        {
            SetId = setId;
            CreationTime = creationTime;
            ShadowCopyId = id;
            OriginalVolume = forVol;
            ShadowCopyVolume = shadowCopyVol;
            OriginatingMachine = originatingMachine;
            ServiceMachine = serviceMachine;
            Provider = provider;
            Context = context;
            Attributes = attributes;
        }
    }
}