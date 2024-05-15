
rule Trojan_Win64_CobaltStrike_FM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.FM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {4c 89 c0 49 f7 e1 4c 89 c1 48 29 d1 48 d1 e9 48 01 ca 48 c1 ea 90 01 01 48 8d 04 92 48 8d 04 80 4c 89 c1 48 29 c1 0f b6 84 0c 90 01 04 48 8d 15 90 01 04 42 32 04 02 48 8b 94 24 90 01 04 42 88 04 02 49 83 c0 90 01 01 4c 39 84 24 90 01 04 77 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}