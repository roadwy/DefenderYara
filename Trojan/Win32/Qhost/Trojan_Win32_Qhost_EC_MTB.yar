
rule Trojan_Win32_Qhost_EC_MTB{
	meta:
		description = "Trojan:Win32/Qhost.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {7a 33 72 30 5f 78 20 4f 6c 75 63 61 6e 20 4f 72 6a 69 6e 61 6c 5c 50 72 6f 6a 65 63 74 31 2e 76 62 70 } //1 z3r0_x Olucan Orjinal\Project1.vbp
		$a_81_1 = {5b 41 75 74 6f 52 75 6e 5d } //1 [AutoRun]
		$a_81_2 = {38 39 2e 32 30 32 2e 31 35 37 2e 31 33 39 } //1 89.202.157.139
		$a_81_3 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //1 C:\WINDOWS\system32\drivers\etc\hosts
		$a_81_4 = {53 68 6f 77 53 75 70 65 72 48 69 64 64 65 6e } //1 ShowSuperHidden
		$a_81_5 = {55 41 43 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 } //1 UACDisableNotify
		$a_81_6 = {45 6e 61 62 6c 65 4c 55 41 } //1 EnableLUA
		$a_81_7 = {44 69 73 61 62 6c 65 53 52 } //1 DisableSR
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}