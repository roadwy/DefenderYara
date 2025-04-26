
rule Trojan_Win64_BlipSlide_B_dha{
	meta:
		description = "Trojan:Win64/BlipSlide.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 83 7c 24 48 ?? 0f 83 50 00 00 00 48 8b 4c 24 40 8a 01 88 44 24 2e 48 83 c1 01 48 8b 54 24 48 e8 ?? ?? ?? ?? 8a 54 24 2e 8a 08 e8 ?? ?? ?? ?? 48 8b 4c 24 30 88 44 24 2f 48 8b 54 24 48 e8 ?? ?? ?? ?? 8a 4c 24 2f 88 08 48 8b 44 24 48 48 83 c0 01 48 89 44 24 48 } //20
	condition:
		((#a_03_0  & 1)*20) >=20
 
}