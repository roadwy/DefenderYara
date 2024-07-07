
rule Trojan_Win32_Wimpixo_E{
	meta:
		description = "Trojan:Win32/Wimpixo.E,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 81 3c 90 01 01 f9 d7 90 90 eb 75 90 01 01 81 7c 90 01 01 04 2e bb 09 d7 75 90 00 } //5
		$a_01_1 = {33 d2 8a d5 32 10 88 14 06 66 0f b6 10 03 d1 b9 bf 58 00 00 69 d2 93 31 00 00 2b ca 40 4f 75 e0 } //5
		$a_03_2 = {66 c7 44 24 90 01 01 d4 07 66 89 44 24 90 01 01 66 89 44 24 90 01 01 66 c7 44 24 90 01 01 0d 00 66 c7 44 24 90 01 01 0c 00 66 c7 44 24 90 01 01 1e 00 90 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5+(#a_03_2  & 1)*5) >=15
 
}