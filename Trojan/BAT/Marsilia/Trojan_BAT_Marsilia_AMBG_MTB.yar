
rule Trojan_BAT_Marsilia_AMBG_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.AMBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {9e 06 06 08 94 06 09 94 58 20 00 01 00 00 5d 94 13 ?? 11 ?? 11 ?? 03 11 ?? 91 11 ?? 61 28 ?? ?? ?? ?? 9c 00 11 ?? 17 58 13 ?? 11 ?? 03 8e 69 fe } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}