
rule Trojan_BAT_RedLineStealer_RP_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 7e 69 00 00 04 28 22 01 00 06 10 01 72 1b 05 00 70 03 72 31 05 00 70 28 7c 00 00 0a 0b 28 31 01 00 06 07 73 d7 00 00 0a 72 35 05 00 70 28 d8 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}