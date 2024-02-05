
rule Trojan_Win64_CobaltStrike_CCAA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {4d 8d 40 01 41 f7 e9 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 41 8b c1 41 ff c1 8d 0c d2 c1 e1 90 01 01 2b c1 48 98 0f b6 4c 04 50 41 30 48 ff 49 83 ea 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}