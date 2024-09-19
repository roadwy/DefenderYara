
rule Trojan_BAT_Formbook_AY_MTB{
	meta:
		description = "Trojan:BAT/Formbook.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 06 11 07 6f ?? 00 00 0a 13 08 08 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 08 6f ?? 00 00 0a 20 ?? ?? ?? 00 2f 0d 08 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 08 6f ?? 00 00 0a 20 ?? ?? ?? 00 2f 0d 08 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 11 07 17 58 13 07 11 07 07 6f ?? 00 00 0a 32 a3 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}