
rule Trojan_Win64_Emotet_MA_MTB{
	meta:
		description = "Trojan:Win64/Emotet.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 f9 8b c2 48 98 48 6b c0 01 48 8b 0d ?? ?? ?? ?? 48 03 c8 48 8b c1 0f b6 00 8b 4c 24 ?? 33 c8 8b c1 48 63 4c 24 ?? 48 6b c9 01 48 8b 54 24 ?? 48 03 d1 48 8b ca 88 01 } //5
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}