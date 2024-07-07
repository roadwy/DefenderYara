
rule Trojan_BAT_SnakeKeyLogger_RDA_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 09 07 09 07 8e 69 5d 91 03 09 91 61 d2 9c 09 17 58 0d 09 03 8e 69 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}