
rule Trojan_BAT_Bladabindi_SPDC_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.SPDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 06 06 6f 90 01 03 0a 06 6f 90 01 03 0a 6f 90 01 03 0a 17 73 90 01 03 0a 0c 00 08 90 00 } //6
	condition:
		((#a_03_0  & 1)*6) >=6
 
}