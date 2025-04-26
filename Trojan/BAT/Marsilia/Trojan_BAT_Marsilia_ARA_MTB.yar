
rule Trojan_BAT_Marsilia_ARA_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 11 0b 11 0f d3 18 5a 58 25 49 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 28 ?? ?? ?? 2b 16 95 1f 64 5e 1f 1e 59 d1 59 d1 53 00 11 0f 17 58 13 0f 11 0f 11 0d fe 04 13 10 11 10 2d c7 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}