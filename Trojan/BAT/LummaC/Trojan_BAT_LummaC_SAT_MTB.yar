
rule Trojan_BAT_LummaC_SAT_MTB{
	meta:
		description = "Trojan:BAT/LummaC.SAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 0a 00 00 04 28 01 00 00 2b 7e ?? ?? ?? 04 25 3a 17 00 00 00 26 7e ?? ?? ?? 04 fe 06 16 00 00 06 73 33 00 00 0a 25 80 ?? ?? ?? 04 28 02 00 00 2b 28 03 00 00 2b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}