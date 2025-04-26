
rule Trojan_BAT_Marsilia_SG_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 20 00 00 0a 11 05 6f 23 00 00 0a 13 09 11 09 28 0a 00 00 06 13 05 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}