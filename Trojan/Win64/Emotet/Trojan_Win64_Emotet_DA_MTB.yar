
rule Trojan_Win64_Emotet_DA_MTB{
	meta:
		description = "Trojan:Win64/Emotet.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 f9 8b c2 48 98 48 8b 0d [0-04] 0f b6 04 01 8b 8c 24 [0-04] 33 c8 8b c1 48 63 8c 24 [0-04] 48 8b 94 24 [0-04] 88 04 0a e9 } //5
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}