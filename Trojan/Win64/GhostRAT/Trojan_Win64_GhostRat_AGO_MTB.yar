
rule Trojan_Win64_GhostRat_AGO_MTB{
	meta:
		description = "Trojan:Win64/GhostRat.AGO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 10 32 45 d7 8b 55 fc 48 63 d2 48 8d 0d ?? ?? ?? ?? 88 04 0a 83 45 fc 01 8b 55 fc } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}