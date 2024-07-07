
rule Trojan_BAT_Androm_AMCH_MTB{
	meta:
		description = "Trojan:BAT/Androm.AMCH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 00 11 05 11 00 11 01 11 05 59 17 59 91 9c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}