
rule Trojan_BAT_Remcos_ACF_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ACF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {5f 13 0c 02 11 08 11 09 6f ?? 00 00 0a 13 0d 12 0d 28 ?? 00 00 0a 13 0e 12 0d 28 ?? 00 00 0a 13 0f 12 0d 28 ?? 00 00 0a 13 10 04 03 6f ?? 00 00 0a 59 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}