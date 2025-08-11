
rule Trojan_BAT_Agensla_PGA_MTB{
	meta:
		description = "Trojan:BAT/Agensla.PGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 13 08 73 ?? 00 00 0a 13 09 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}