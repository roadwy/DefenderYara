
rule Trojan_BAT_Zilla_ZZM_MTB{
	meta:
		description = "Trojan:BAT/Zilla.ZZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 06 11 04 6f ?? 00 00 0a 13 07 07 25 13 08 72 ?? 09 00 70 11 08 72 ?? 09 00 70 6f ?? 00 00 0a 12 07 28 ?? 00 00 0a d6 6f ?? 00 00 0a 00 07 25 13 08 } //10
		$a_01_1 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}