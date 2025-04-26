
rule Trojan_BAT_LummaC_ZAA_MTB{
	meta:
		description = "Trojan:BAT/LummaC.ZAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 07 a2 25 17 72 27 03 00 70 28 ?? ?? 00 0a 72 2f 03 00 70 72 a9 03 00 70 7e 42 00 00 0a 28 ?? ?? 00 0a 28 ?? ?? 00 0a a2 25 18 17 8c 71 00 00 01 a2 25 19 17 8d 20 00 00 01 25 16 72 b7 03 00 70 a2 a2 14 0d 12 03 28 ?? ?? 00 06 28 34 00 00 0a 0c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}