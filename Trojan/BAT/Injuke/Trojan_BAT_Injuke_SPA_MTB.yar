
rule Trojan_BAT_Injuke_SPA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.SPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 04 06 11 04 9a 1f 10 28 ?? ?? ?? 0a d2 9c 11 04 17 58 13 04 11 04 06 8e 69 fe 04 13 05 11 05 2d dd } //9
	condition:
		((#a_03_0  & 1)*9) >=9
 
}