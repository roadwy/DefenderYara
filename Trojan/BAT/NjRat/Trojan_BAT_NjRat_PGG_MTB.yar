
rule Trojan_BAT_NjRat_PGG_MTB{
	meta:
		description = "Trojan:BAT/NjRat.PGG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 06 11 06 16 06 06 14 6f ?? ?? ?? 0a a2 00 11 06 17 14 a2 00 11 06 14 14 14 17 28 ?? ?? ?? 0a 26 00 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}