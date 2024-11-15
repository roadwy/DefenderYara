
rule Trojan_BAT_Heracles_KAY_MTB{
	meta:
		description = "Trojan:BAT/Heracles.KAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 7e 05 00 00 04 14 28 1a 00 00 0a 0b 16 2b 01 16 45 03 00 00 00 02 00 00 00 } //3
		$a_01_1 = {2b 00 00 00 2b 32 07 2c 26 72 01 00 00 70 d0 05 00 00 02 28 } //3
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3) >=6
 
}