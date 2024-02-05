
rule Trojan_Win64_CobaltStrike_MKVB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MKVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b f0 41 c0 e6 90 01 01 8b c8 c1 e9 90 01 01 41 32 ce 80 e1 90 01 01 41 32 ce 48 8b 55 90 01 01 4c 8b 45 90 01 01 49 3b d0 73 90 01 01 48 8d 42 90 01 01 48 89 45 90 01 01 48 8d 45 90 01 01 49 83 f8 90 01 01 48 0f 43 45 90 01 01 88 0c 10 c6 44 10 01 90 01 01 eb 90 01 01 44 0f b6 c9 48 8d 4d 90 01 01 e8 90 01 04 4d 3b fc 0f 83 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}