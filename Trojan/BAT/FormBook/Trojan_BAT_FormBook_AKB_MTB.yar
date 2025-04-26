
rule Trojan_BAT_FormBook_AKB_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {9c 0b 16 0c 2b 1f 07 08 91 1f 7f 26 26 04 07 08 91 6f ?? 00 00 0a 06 08 06 08 94 18 5a 1f 64 5d 9e 08 17 58 0c 08 03 32 dd } //3
		$a_03_1 = {5a 0a 06 17 28 ?? 00 00 0a 0a 03 19 8d ?? 00 00 01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 } //1
		$a_01_2 = {41 00 62 00 64 00 75 00 6c 00 6c 00 61 00 68 00 48 00 61 00 73 00 73 00 61 00 6e 00 41 00 62 00 64 00 6f 00 5f 00 4c 00 61 00 62 00 35 00 } //2 AbdullahHassanAbdo_Lab5
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*1+(#a_01_2  & 1)*2) >=6
 
}