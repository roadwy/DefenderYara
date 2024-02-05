
rule Trojan_Win32_CobaltStrike_LKAD_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.LKAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 56 33 ff 57 ff 15 } //01 00 
		$a_03_1 = {b1 66 30 88 90 01 04 40 3b c6 7c f5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}