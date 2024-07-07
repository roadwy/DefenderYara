
rule Trojan_Win32_TeslaCrypt_GHC_MTB{
	meta:
		description = "Trojan:Win32/TeslaCrypt.GHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {52 65 63 6f 76 65 72 79 4d 61 6e 75 61 6c 2e 68 74 6d 6c } //1 RecoveryManual.html
		$a_01_1 = {72 65 61 64 6d 65 2e 74 78 74 } //1 readme.txt
		$a_01_2 = {62 68 76 2e 65 6e 63 72 79 70 74 69 6f 6e 2e 65 6e 63 72 79 70 74 5f 66 69 6c 65 73 } //1 bhv.encryption.encrypt_files
		$a_01_3 = {62 68 76 2e 72 61 6e 73 6f 6d 2e 72 61 6e 73 6f 6d 5f 6e 6f 74 65 } //1 bhv.ransom.ransom_note
		$a_01_4 = {45 72 72 6f 72 20 63 68 65 63 6b 69 6e 67 20 66 6f 72 20 72 61 6e 73 6f 6d 77 61 72 65 20 66 69 6c 65 73 } //1 Error checking for ransomware files
		$a_01_5 = {55 6e 61 62 6c 65 20 74 6f 20 67 65 74 20 53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 73 2c 20 6d 61 79 20 62 65 20 75 6e 61 62 6c 65 20 74 6f 20 63 6c 65 61 6e 20 75 70 20 63 68 69 6c 64 20 70 72 6f 63 65 73 73 65 73 } //1 Unable to get SeDebugPrivileges, may be unable to clean up child processes
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}