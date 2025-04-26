
rule Trojan_BAT_Barys_ND_MTB{
	meta:
		description = "Trojan:BAT/Barys.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 03 06 58 8f 27 00 00 02 04 28 ?? 01 00 06 0d 06 17 62 0a 06 09 58 0a 07 09 08 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}