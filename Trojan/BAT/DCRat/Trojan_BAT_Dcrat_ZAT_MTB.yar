
rule Trojan_BAT_Dcrat_ZAT_MTB{
	meta:
		description = "Trojan:BAT/Dcrat.ZAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 00 04 02 7b ?? 01 00 04 02 7b ?? 01 00 04 91 02 7b ?? 01 00 04 02 7b ?? 01 00 04 91 58 20 00 01 00 00 5d 91 0c 06 07 03 07 91 08 61 d2 9c 07 17 58 0b 07 03 8e 69 } //6
		$a_03_1 = {23 07 02 7b ?? 01 00 04 09 91 58 03 09 06 5d 91 58 20 00 01 00 00 5d 0b 02 09 07 28 ?? 00 00 06 09 17 58 0d 09 20 00 01 00 00 32 d5 } //5
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}