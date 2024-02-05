
rule Trojan_Win32_CobaltStrike_RFA_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.RFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {8a a5 08 00 c7 45 } //01 00 
		$a_03_1 = {8b d8 83 c3 04 e8 90 01 04 2b d8 01 5d 90 01 01 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 72 90 02 05 c7 90 02 05 00 10 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}