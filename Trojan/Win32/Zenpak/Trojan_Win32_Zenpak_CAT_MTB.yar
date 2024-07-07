
rule Trojan_Win32_Zenpak_CAT_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.CAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 bc 8b 08 8b 55 c4 8b 32 8b 7d cc 8b 1f 8b 02 8b 55 b8 8b 12 8b 7d c8 8b 3f 0f b6 04 03 0f b6 0c 11 31 c8 88 04 37 e9 } //2
		$a_03_1 = {8b 4d c4 8b 11 2d 90 02 04 01 c2 89 55 ac 8b 45 c4 8b 4d ac 89 08 e9 90 00 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}