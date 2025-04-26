
rule Trojan_BAT_Marsilia_KAD_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 9a 13 06 06 1f 0c 28 ?? 00 00 0a 6a 02 58 09 18 5a 6a 58 28 ?? 00 00 0a 18 28 ?? 00 00 06 16 28 ?? 00 00 0a 13 07 11 06 25 2d 06 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}