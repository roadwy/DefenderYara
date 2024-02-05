
rule Backdoor_Win32_CobaltStrike_MXK_MTB{
	meta:
		description = "Backdoor:Win32/CobaltStrike.MXK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 01 33 d2 2b 05 90 01 04 f7 35 90 01 04 88 06 46 43 83 c1 04 3b df 7c 90 00 } //01 00 
		$a_01_1 = {8b 03 33 d2 f7 f5 41 83 c3 04 46 88 51 ff 3b f7 7c ee } //00 00 
	condition:
		any of ($a_*)
 
}