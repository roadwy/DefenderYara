
rule Trojan_BAT_RedLine_RDB_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {03 19 04 5a 61 d1 2a } //2
		$a_01_1 = {03 04 61 d1 2a } //2
		$a_01_2 = {03 18 61 d1 2a } //2
		$a_03_3 = {2a 56 02 7b ?? ?? ?? ?? 04 02 7b ?? ?? ?? ?? 8e 69 5d 93 03 61 d2 2a } //2
		$a_01_4 = {8c 38 00 00 01 07 18 28 0e 00 00 2b 28 6e 00 00 0a 13 07 11 07 08 18 28 0e 00 00 2b 28 6e 00 00 0a 13 07 11 07 09 18 17 8d 0b 00 00 01 25 16 11 06 a2 28 6e 00 00 0a 13 07 11 07 11 04 18 28 0e 00 00 2b 28 6e 00 00 0a 13 07 11 07 11 05 17 18 8d 0b 00 00 01 25 16 16 8c 38 00 00 01 a2 28 6e 00 00 0a 13 07 2a } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_03_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}