
rule Trojan_Win32_CobaltStrike_RA_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 44 24 0c 40 00 00 00 c7 44 24 08 00 30 00 00 89 44 24 04 c7 04 24 00 00 00 00 ff 15 90 02 30 89 c1 83 e1 07 d2 ca 88 54 03 ff 89 c2 83 c0 01 39 d6 75 e5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}