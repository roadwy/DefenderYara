
rule Ransom_Linux_BQTLock_A_MTB{
	meta:
		description = "Ransom:Linux/BQTLock.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {42 51 54 4c 6f 63 6b 43 6c 69 65 6e 74 } //1 BQTLockClient
		$a_01_1 = {72 6d 20 2d 72 66 20 2f 6d 6e 74 2f 62 61 63 6b 75 70 73 2f 2a } //1 rm -rf /mnt/backups/*
		$a_01_2 = {2f 74 6d 70 2f 62 71 74 5f 6c 6f 67 2e 74 78 74 } //1 /tmp/bqt_log.txt
		$a_01_3 = {65 6e 63 72 79 70 74 65 64 5f 63 6f 75 6e 74 } //1 encrypted_count
		$a_01_4 = {62 74 72 66 73 20 73 75 62 76 6f 6c 75 6d 65 20 64 65 6c 65 74 65 20 2f 73 6e 61 70 73 68 6f 74 73 2f 2a } //1 btrfs subvolume delete /snapshots/*
		$a_01_5 = {7a 66 73 20 64 65 73 74 72 6f 79 20 2d 72 20 2d 66 20 70 6f 6f 6c 2f 73 6e 61 70 73 68 6f 74 73 } //1 zfs destroy -r -f pool/snapshots
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}