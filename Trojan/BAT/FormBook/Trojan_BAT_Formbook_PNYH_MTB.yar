
rule Trojan_BAT_Formbook_PNYH_MTB{
	meta:
		description = "Trojan:BAT/Formbook.PNYH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 02 06 07 28 ?? ?? ?? ?? 0c 04 03 6f ?? ?? ?? ?? 59 0d 03 08 09 28 ?? ?? ?? ?? 00 00 07 17 58 0b 07 02 6f ?? ?? ?? ?? 2f 0b 03 6f ?? ?? ?? ?? 04 fe 04 2b 01 16 13 04 11 04 2d c4 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}