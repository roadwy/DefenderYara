
rule Trojan_BAT_Bladabindi_NYK_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NYK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 b8 88 00 00 28 21 00 00 0a 28 40 00 00 0a 0d 16 13 04 2b 1f 09 11 04 9a } //1
		$a_01_1 = {15 a2 15 09 01 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 4e 00 00 00 21 00 00 00 20 00 00 00 3c 03 00 00 12 00 00 00 77 00 00 00 16 00 00 00 0b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}