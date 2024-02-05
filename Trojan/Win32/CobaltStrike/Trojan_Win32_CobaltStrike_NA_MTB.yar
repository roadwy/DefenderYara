
rule Trojan_Win32_CobaltStrike_NA_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 10 00 00 56 6a 00 89 90 01 02 ff 15 90 00 } //02 00 
		$a_01_1 = {6a 00 6a 03 6a 00 6a 01 68 00 00 00 80 50 ff 15 } //02 00 
		$a_01_2 = {8b 16 89 17 83 c7 04 83 c6 04 83 e9 01 75 f1 8b c8 83 e1 03 74 13 8a 06 88 07 46 47 49 75 f7 } //00 00 
	condition:
		any of ($a_*)
 
}