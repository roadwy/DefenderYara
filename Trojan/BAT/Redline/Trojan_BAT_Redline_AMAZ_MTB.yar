
rule Trojan_BAT_Redline_AMAZ_MTB{
	meta:
		description = "Trojan:BAT/Redline.AMAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 06 02 06 91 66 d2 9c 02 06 8f ?? 00 00 01 25 71 ?? 00 00 01 1f ?? 58 d2 81 ?? 00 00 01 02 06 8f ?? 00 00 01 25 71 ?? 00 00 01 1f 32 59 d2 81 ?? 00 00 01 00 06 17 58 0a 06 02 8e 69 fe ?? 0b 07 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Redline_AMAZ_MTB_2{
	meta:
		description = "Trojan:BAT/Redline.AMAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {91 66 d2 9c 02 11 ?? 8f ?? 00 00 01 25 71 ?? 00 00 01 1f ?? 58 d2 81 ?? 00 00 01 02 11 ?? 8f ?? 00 00 01 25 71 ?? 00 00 01 20 ?? 00 00 00 59 d2 81 ?? 00 00 01 00 11 ?? 17 58 13 ?? 11 ?? 02 8e 69 fe } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}