
rule Trojan_BAT_Noon_ZTQ_MTB{
	meta:
		description = "Trojan:BAT/Noon.ZTQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 11 04 09 6f ?? 00 00 0a 13 09 12 09 28 ?? 00 00 0a 0a 12 09 28 ?? 00 00 0a 0b 12 09 28 ?? 00 00 0a 0c 06 13 06 07 13 06 08 13 06 11 06 11 06 11 06 28 ?? 00 00 0a 13 05 03 11 04 09 11 05 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}