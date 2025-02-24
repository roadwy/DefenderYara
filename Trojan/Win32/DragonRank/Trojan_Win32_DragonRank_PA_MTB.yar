
rule Trojan_Win32_DragonRank_PA_MTB{
	meta:
		description = "Trojan:Win32/DragonRank.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-20] 2e 00 [0-08] 2f 00 7a 00 7a 00 31 00 2e 00 70 00 68 00 70 00 } //2
		$a_01_1 = {5c 48 74 74 70 4d 6f 64 52 65 73 70 44 4c 4c 78 38 36 2e 70 64 62 } //1 \HttpModRespDLLx86.pdb
		$a_01_2 = {4d 00 4a 00 31 00 32 00 62 00 6f 00 74 00 7c 00 6d 00 73 00 6e 00 62 00 6f 00 74 00 7c 00 59 00 61 00 68 00 6f 00 6f 00 7c 00 62 00 69 00 6e 00 67 00 62 00 6f 00 74 00 7c 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 7c 00 59 00 61 00 6e 00 64 00 65 00 78 00 42 00 6f 00 74 00 7c 00 44 00 6f 00 74 00 42 00 6f 00 74 00 } //1 MJ12bot|msnbot|Yahoo|bingbot|google|YandexBot|DotBot
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}