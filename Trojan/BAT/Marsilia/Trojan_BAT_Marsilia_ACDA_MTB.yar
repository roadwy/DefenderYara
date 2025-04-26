
rule Trojan_BAT_Marsilia_ACDA_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.ACDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 11 04 91 13 05 00 11 05 13 06 06 07 11 06 1f 0d 61 20 8f 00 00 00 61 20 e7 00 00 00 61 20 d3 00 00 00 61 1f 4f 61 20 d9 00 00 00 61 20 f0 00 00 00 61 20 d9 00 00 00 61 20 f6 00 00 00 61 20 9f 00 00 00 61 20 ee 00 00 00 61 1f 69 61 28 ?? 00 00 0a 9d 07 17 58 0b 00 11 04 17 58 13 04 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}