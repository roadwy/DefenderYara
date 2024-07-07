
rule Trojan_Win32_Tnega_RK_MTB{
	meta:
		description = "Trojan:Win32/Tnega.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {13 0b 16 6a 13 0c 12 05 1f 0e 7e 90 01 03 0a 12 03 7c 90 01 03 04 1f 40 20 90 01 03 08 7e 90 01 03 0a 28 90 01 03 06 6e 16 6a 3d 90 01 03 00 11 05 28 90 01 03 06 12 06 7e 90 01 03 0a 7e 90 01 03 0a 12 0a 12 0b 18 11 09 1a 28 90 01 03 06 6e 72 90 01 03 70 28 90 01 03 06 7b 90 01 03 04 90 00 } //1
		$a_80_1 = {5a 43 55 56 71 6f 72 53 74 32 4c 55 33 64 6d 48 68 6e 61 38 56 5a 57 75 6d 46 41 41 33 51 50 57 } //ZCUVqorSt2LU3dmHhna8VZWumFAA3QPW  1
		$a_80_2 = {71 3c 2f 32 6e 4b 2a 3e 44 65 21 27 37 70 2f 56 } //q</2nK*>De!'7p/V  1
	condition:
		((#a_03_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Tnega_RK_MTB_2{
	meta:
		description = "Trojan:Win32/Tnega.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4a 6f 69 6e 44 6f 6d 61 69 6e 2e 65 78 65 } //1 JoinDomain.exe
		$a_01_1 = {43 72 65 64 55 49 50 72 6f 6d 70 74 46 6f 72 43 72 65 64 65 6e 74 69 61 6c 73 } //1 CredUIPromptForCredentials
		$a_01_2 = {74 61 72 67 65 74 4e 61 6d 65 } //1 targetName
		$a_01_3 = {54 6f 55 6e 69 63 6f 64 65 } //1 ToUnicode
		$a_01_4 = {73 65 74 5f 55 73 65 53 79 73 74 65 6d 50 61 73 73 77 6f 72 64 43 68 61 72 } //1 set_UseSystemPasswordChar
		$a_81_5 = {4a 47 52 76 62 57 46 70 62 69 41 39 49 43 4a 79 5a 43 35 6e 62 79 35 30 61 43 49 4e 43 69 52 77 59 58 4e 7a 64 32 39 79 5a 43 41 39 49 43 4a 79 5a 48 42 41 4e 54 56 33 4d 48 4a 6b 49 69 42 38 49 45 4e 76 62 6e 5a 6c 63 6e 52 } //1 JGRvbWFpbiA9ICJyZC5nby50aCINCiRwYXNzd29yZCA9ICJyZHBANTV3MHJkIiB8IENvbnZlcnR
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}