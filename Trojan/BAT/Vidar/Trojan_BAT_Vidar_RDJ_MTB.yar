
rule Trojan_BAT_Vidar_RDJ_MTB{
	meta:
		description = "Trojan:BAT/Vidar.RDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 28 63 00 00 0a 13 08 11 08 11 06 74 25 00 00 01 73 3f 00 00 0a 0d 18 0c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}