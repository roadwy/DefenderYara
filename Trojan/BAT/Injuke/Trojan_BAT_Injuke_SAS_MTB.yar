
rule Trojan_BAT_Injuke_SAS_MTB{
	meta:
		description = "Trojan:BAT/Injuke.SAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 0b 00 00 06 72 a1 00 00 70 7e 03 00 00 04 6f 14 00 00 0a 74 01 00 00 1b } //2
		$a_01_1 = {11 01 11 03 11 00 11 03 91 72 61 00 00 70 28 03 00 00 0a 59 d2 9c 20 05 00 00 00 7e 10 00 00 04 7b 52 00 00 04 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}