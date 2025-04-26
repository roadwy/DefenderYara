
rule Trojan_Win32_Bodegun_EH_MTB{
	meta:
		description = "Trojan:Win32/Bodegun.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {62 68 76 2e 65 6e 63 72 79 70 74 69 6f 6e 2e 65 6e 63 72 79 70 74 5f 66 69 6c 65 73 } //1 bhv.encryption.encrypt_files
		$a_81_1 = {62 68 76 2e 72 61 6e 73 6f 6d 2e 72 61 6e 73 6f 6d 5f 6e 6f 74 65 } //1 bhv.ransom.ransom_note
		$a_81_2 = {55 6e 61 62 6c 65 20 74 6f 20 67 65 74 20 53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 73 2c 20 6d 61 79 20 62 65 20 75 6e 61 62 6c 65 20 74 6f 20 63 6c 65 61 6e 20 75 70 20 63 68 69 6c 64 20 70 72 6f 63 65 73 73 65 73 } //1 Unable to get SeDebugPrivileges, may be unable to clean up child processes
		$a_01_3 = {4c 6f 63 6b 42 69 74 5f 52 61 6e 73 6f 6d 77 61 72 65 2e 68 74 61 } //1 LockBit_Ransomware.hta
		$a_01_4 = {52 65 73 74 6f 72 65 2d 4d 79 2d 46 69 6c 65 73 2e 74 78 74 } //1 Restore-My-Files.txt
		$a_01_5 = {2e 6c 6f 63 6b 62 69 74 } //1 .lockbit
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}