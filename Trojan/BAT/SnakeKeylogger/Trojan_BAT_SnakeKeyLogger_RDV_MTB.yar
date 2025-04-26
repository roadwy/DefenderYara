
rule Trojan_BAT_SnakeKeyLogger_RDV_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 05 6f 5f 01 00 0a 13 06 73 3d 00 00 0a 0a 03 75 13 00 00 1b 73 60 01 00 0a 0c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}