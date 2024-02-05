
rule Trojan_Win32_CobaltStrike_EO_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.EO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 02 8b 45 d8 03 45 b0 03 45 e8 89 45 b4 90 01 07 8b d8 03 5d b4 90 01 07 2b d8 90 01 07 2b d8 8b 45 ec 31 18 90 01 07 8b 55 e8 83 c2 04 03 c2 89 45 e8 90 01 07 83 c0 04 01 45 ec 8b 45 e8 3b 45 e4 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}