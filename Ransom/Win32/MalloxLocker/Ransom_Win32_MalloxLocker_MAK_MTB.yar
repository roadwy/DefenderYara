
rule Ransom_Win32_MalloxLocker_MAK_MTB{
	meta:
		description = "Ransom:Win32/MalloxLocker.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_80_0 = {2f 63 20 62 63 64 65 64 69 74 20 2f 73 65 74 20 7b 63 75 72 72 65 6e 74 7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 6e 6f } ///c bcdedit /set {current} recoveryenabled no  1
		$a_80_1 = {52 45 43 4f 56 45 52 59 20 49 4e 46 4f 52 4d 41 54 49 4f 4e 2e 74 78 74 } //RECOVERY INFORMATION.txt  1
		$a_02_2 = {48 00 4f 00 57 00 20 00 54 00 4f 00 20 00 52 00 45 00 43 00 4f 00 56 00 45 00 52 00 [0-0a] 2e 00 54 00 58 00 54 00 } //1
		$a_02_3 = {48 4f 57 20 54 4f 20 52 45 43 4f 56 45 52 [0-0a] 2e 54 58 54 } //1
		$a_80_4 = {64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //delete shadows /all /quiet  1
		$a_80_5 = {59 4f 55 52 20 46 49 4c 45 53 20 41 52 45 20 45 4e 43 52 59 50 54 45 44 } //YOUR FILES ARE ENCRYPTED  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=5
 
}