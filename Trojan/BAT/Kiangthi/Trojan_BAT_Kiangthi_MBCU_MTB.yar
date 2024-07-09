
rule Trojan_BAT_Kiangthi_MBCU_MTB{
	meta:
		description = "Trojan:BAT/Kiangthi.MBCU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {18 2d 2e 26 16 2d 33 18 25 2c 03 2d 2a 17 25 2c e8 8d ?? 00 00 01 25 16 72 45 00 00 70 a2 15 2d 1b 26 2a 16 2c 1c 26 26 } //1
		$a_01_1 = {45 00 42 00 53 00 44 00 43 00 42 00 52 00 53 00 2e 00 64 00 6c 00 6c 00 } //1 EBSDCBRS.dll
		$a_01_2 = {57 3f a2 1f 09 0f 00 00 00 3a 00 13 00 06 00 00 01 00 00 00 ec 00 00 00 bf 00 00 00 7c 02 00 00 c8 04 00 00 da 03 00 00 1b 00 00 00 37 02 00 00 39 00 00 00 ee } //1
		$a_01_3 = {1e 2d 12 26 26 2b e7 28 73 00 00 06 2b ea 28 34 00 00 0a 2b e9 6f 57 00 00 0a 2b e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}