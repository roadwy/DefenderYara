
rule Trojan_BAT_MassLogger_EHJY_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.EHJY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 11 10 1f 0a 58 13 10 11 0c 11 2c 1f 1f 5a 58 13 0c 11 0d 11 2c 61 13 0d 11 2c 1f 32 5d 16 fe 01 13 2d 11 2d 2c 20 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}