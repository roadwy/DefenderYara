
rule Trojan_BAT_Marsilia_AMAD_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.AMAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 06 07 28 ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0c 02 0d 08 09 16 09 8e b7 6f ?? 00 00 0a 13 04 dd ?? 00 00 00 dd } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}