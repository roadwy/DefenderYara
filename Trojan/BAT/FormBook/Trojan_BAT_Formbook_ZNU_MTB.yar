
rule Trojan_BAT_Formbook_ZNU_MTB{
	meta:
		description = "Trojan:BAT/Formbook.ZNU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {26 16 58 06 17 18 28 ?? 00 00 0a 26 16 58 13 08 02 11 07 11 08 6f ?? 00 00 0a 13 09 12 09 28 ?? 00 00 0a 13 0a 12 09 28 ?? 00 00 0a 13 0b 12 09 28 ?? 00 00 0a 13 0c 04 03 6f ?? 00 00 0a 59 13 0d 11 0d 19 32 4f } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}