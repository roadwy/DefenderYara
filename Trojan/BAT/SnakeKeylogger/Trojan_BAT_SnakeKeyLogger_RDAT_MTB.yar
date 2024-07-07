
rule Trojan_BAT_SnakeKeyLogger_RDAT_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d 91 61 07 09 17 58 08 5d 91 59 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}