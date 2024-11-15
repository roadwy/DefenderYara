
rule Trojan_BAT_Injuke_AACA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.AACA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 06 02 06 91 66 d2 9c 02 06 8f ?? 00 00 01 25 71 ?? 00 00 01 1f 58 59 d2 81 ?? 00 00 01 02 06 8f ?? 00 00 01 25 71 ?? 00 00 01 1f 44 59 d2 81 ?? 00 00 01 00 06 17 58 0a 06 02 8e 69 fe 04 13 0b 11 0b 3a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}