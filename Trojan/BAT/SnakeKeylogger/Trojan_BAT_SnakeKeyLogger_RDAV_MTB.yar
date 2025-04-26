
rule Trojan_BAT_SnakeKeyLogger_RDAV_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 09 91 11 0c 61 07 11 0d 91 59 13 0e 11 0e 20 00 01 00 00 58 13 0f 07 11 09 11 0f 20 ff 00 00 00 5f d2 9c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}