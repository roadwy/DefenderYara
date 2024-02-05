
rule Trojan_Win64_CobaltStrike_CD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {49 63 c9 4d 8d 52 90 01 01 48 8b c3 41 ff c1 48 f7 e1 48 c1 ea 90 01 01 48 6b c2 90 01 01 48 2b c8 0f b6 44 8c 90 01 01 41 30 42 90 01 01 41 81 f9 90 01 04 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}