
rule Trojan_BAT_Marsilia_SPVG_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.SPVG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 02 8e 69 17 58 11 04 58 18 28 ?? ?? ?? 06 20 ?? ?? ?? 00 28 ?? ?? ?? 0a d2 9c 11 04 17 58 13 04 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}