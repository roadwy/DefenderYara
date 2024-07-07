
rule Trojan_BAT_Marsilia_AMA_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.AMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 06 17 6f 90 01 01 00 00 0a 06 02 16 9a 6f 90 01 01 00 00 0a 06 17 6f 90 01 01 00 00 0a 25 06 6f 90 01 01 00 00 0a 06 02 17 9a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}