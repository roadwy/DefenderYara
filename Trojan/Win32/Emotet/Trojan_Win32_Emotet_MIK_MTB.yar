
rule Trojan_Win32_Emotet_MIK_MTB{
	meta:
		description = "Trojan:Win32/Emotet.MIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 f0 01 c8 83 c0 44 8b 4d c8 69 c9 ?? ?? ?? ?? 01 ce 81 c6 ?? ?? ?? ?? 8b 0e 8b 75 b8 33 0e 8b 00 29 da 8b 5d c4 81 f3 db d9 75 15 89 3c 24 89 44 24 04 89 4c 24 08 89 5d b4 89 55 b0 89 4d ac e8 } //5
		$a_03_1 = {89 d7 81 f7 e4 2c 10 4b 31 db b8 e1 20 4f 43 29 d0 19 f3 89 5c 24 ?? 89 44 24 10 8b 44 24 ?? 8b 54 24 10 29 fa 19 f0 89 54 24 04 89 04 24 73 } //3
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*3) >=8
 
}