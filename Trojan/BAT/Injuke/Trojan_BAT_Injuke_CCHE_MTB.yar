
rule Trojan_BAT_Injuke_CCHE_MTB{
	meta:
		description = "Trojan:BAT/Injuke.CCHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 11 04 28 ?? 03 00 06 00 25 17 28 ?? 03 00 06 00 25 18 28 ?? 03 00 06 00 25 07 28 ?? 03 00 06 00 13 08 20 ?? 00 00 00 38 ?? fe ff ff 08 11 04 73 ?? ?? ?? ?? 09 07 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}