
rule Trojan_Win64_Emotet_PBG_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e6 8b c6 8b ce 2b c2 ff c6 d1 90 01 01 03 c2 c1 e8 90 01 01 6b c0 90 01 01 2b c8 48 63 c1 42 0f b6 04 10 43 32 44 07 90 01 01 41 88 40 90 01 01 41 3b f4 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Emotet_PBG_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.PBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 03 c1 48 63 0d 90 01 04 48 03 c1 48 63 0d 90 01 04 48 03 4c 24 90 01 01 0f b6 04 01 03 44 24 90 01 01 8b 4c 24 90 01 01 33 c8 8b c1 8b 0d 90 01 04 8b 14 24 2b d1 8b ca 90 00 } //1
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}