
rule Trojan_BAT_MassLogger_EHKA_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.EHKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 04 06 09 93 13 05 06 09 06 11 04 93 9d 06 11 04 11 05 9d 00 09 17 58 0d 09 06 8e 69 fe 04 13 06 11 06 2d cc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}