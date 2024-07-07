
rule Trojan_Win32_KillMBR_AR_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 75 73 74 6f 6d 4d 42 52 5f 43 72 65 61 74 65 64 5f 42 79 5f 57 6f 62 62 79 43 68 69 70 } //10 CustomMBR_Created_By_WobbyChip
		$a_01_1 = {43 72 65 61 74 65 64 20 42 79 20 41 6e 67 65 6c 20 43 61 73 74 69 6c 6c 6f 2e 20 59 6f 75 72 20 43 6f 6d 70 75 74 65 72 20 48 61 73 20 42 65 65 6e 20 54 72 61 73 68 65 64 2e } //4 Created By Angel Castillo. Your Computer Has Been Trashed.
		$a_01_2 = {2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 } //1 .\PhysicalDrive
		$a_01_3 = {77 69 6e 69 6e 69 74 2e 65 78 65 } //1 wininit.exe
		$a_01_4 = {73 65 72 76 69 63 65 73 2e 65 78 65 } //1 services.exe
		$a_01_5 = {63 73 72 73 73 2e 65 78 65 } //1 csrss.exe
		$a_01_6 = {41 6c 6c 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //4 All of your files have been encrypted
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*4+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*4) >=16
 
}