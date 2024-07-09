
rule Trojan_Win32_Fareit_DEL_MTB{
	meta:
		description = "Trojan:Win32/Fareit.DEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {61 6e 6d 4e 38 32 73 4c 6a 52 } //1 anmN82sLjR
		$a_81_1 = {49 43 31 39 75 31 35 4a 31 34 64 6e 37 52 34 4a 33 50 35 51 61 76 4a 39 62 55 } //1 IC19u15J14dn7R4J3P5QavJ9bU
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Fareit_DEL_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.DEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_81_0 = {73 32 59 58 45 4b 46 41 30 4b 6b } //1 s2YXEKFA0Kk
		$a_81_1 = {35 56 53 4b 30 63 34 50 50 68 5a 41 59 61 54 74 4e } //1 5VSK0c4PPhZAYaTtN
		$a_02_2 = {89 1e a1 60 bc 47 00 03 06 8a 00 34 ?? 8b 15 60 bc 47 00 03 16 88 02 ?? ?? 43 81 fb ?? ?? ?? ?? 75 } //2
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_02_2  & 1)*2) >=2
 
}
rule Trojan_Win32_Fareit_DEL_MTB_3{
	meta:
		description = "Trojan:Win32/Fareit.DEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {59 6c 63 46 33 6e 6b 4f 4a 4f 4b 51 38 38 53 4a 73 55 61 7a 42 50 76 45 6d 72 52 49 52 30 44 35 74 57 42 64 6b 54 } //1 YlcF3nkOJOKQ88SJsUazBPvEmrRIR0D5tWBdkT
		$a_81_1 = {4e 74 63 31 62 63 6c 61 50 65 41 46 71 6e 58 39 63 75 48 } //1 Ntc1bclaPeAFqnX9cuH
		$a_81_2 = {6f 43 32 6a 32 45 59 4c 35 78 57 61 51 7a 76 6a } //1 oC2j2EYL5xWaQzvj
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Fareit_DEL_MTB_4{
	meta:
		description = "Trojan:Win32/Fareit.DEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {38 6e 54 62 63 6c 42 4c 62 55 7a 69 58 31 42 58 63 6b 74 33 52 71 61 37 57 53 4d 32 64 39 4b 4a 6e 56 4c 63 48 55 44 } //1 8nTbclBLbUziX1BXckt3Rqa7WSM2d9KJnVLcHUD
		$a_81_1 = {43 66 42 39 39 61 65 7a 65 34 4f 77 } //1 CfB99aeze4Ow
		$a_81_2 = {36 33 37 32 57 52 36 69 6a 4f 34 44 77 54 77 61 41 6c 72 4c 6c 79 75 4a } //1 6372WR6ijO4DwTwaAlrLlyuJ
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}