
rule Trojan_BAT_GhostRat_AGR_MTB{
	meta:
		description = "Trojan:BAT/GhostRat.AGR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 11 09 1e 5b 91 1d 11 09 1e 5d 59 1f 1f 5f 63 17 5f 60 7d ?? ?? ?? 04 11 0c 11 04 17 59 2f 10 11 0a 11 0a 7b ?? ?? ?? 04 17 62 7d ?? ?? ?? 04 11 09 17 58 13 09 11 0c 17 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}