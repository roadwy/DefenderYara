
rule Trojan_BAT_Bladabindi_M_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {72 01 00 00 70 0a 17 0b 07 2c 43 73 90 01 03 0a 0c 73 90 01 03 0a 0d 09 17 6f 90 01 03 0a 09 72 90 01 03 70 6f 90 01 03 0a 09 72 90 01 03 70 06 28 90 01 03 0a 6f 90 01 03 0a 08 09 6f 90 01 03 0a 08 6f 90 01 03 0a 26 08 6f 90 01 03 0a 2a 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}