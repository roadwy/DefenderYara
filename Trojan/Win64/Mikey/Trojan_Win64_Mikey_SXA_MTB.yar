
rule Trojan_Win64_Mikey_SXA_MTB{
	meta:
		description = "Trojan:Win64/Mikey.SXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 0f b7 00 66 45 85 c0 74 27 66 44 89 01 44 0f b7 40 02 66 45 85 c0 74 18 66 44 89 41 02 48 83 c0 04 48 83 c1 04 83 c2 02 81 fa 04 01 00 00 7c cf } //3
		$a_01_1 = {8b c1 99 2b c2 d1 f8 ff c8 4c 8b c6 41 80 fb 2d 41 0f 94 c0 48 63 d8 4c 3b c3 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}