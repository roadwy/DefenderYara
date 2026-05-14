
rule Trojan_BAT_Androm_AD_MTB{
	meta:
		description = "Trojan:BAT/Androm.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0a 11 08 6f 10 00 00 0a 17 73 11 00 00 0a 13 04 38 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}