
rule Trojan_Win64_Emotet_PBI_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 00 43 00 2e 00 45 00 58 00 45 00 } //1 SC.EXE
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win64_Emotet_PBI_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.PBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 03 c8 48 8b c1 0f b6 00 8b 4c 24 ?? 33 c8 8b c1 48 63 4c 24 ?? 48 6b c9 01 48 8b 54 24 ?? 48 03 d1 48 8b ca 88 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}