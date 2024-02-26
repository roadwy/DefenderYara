
rule Trojan_Win32_CobaltStrike_CCDE_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.CCDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 10 00 00 83 c5 03 55 53 ff 15 } //01 00 
		$a_03_1 = {88 0e 0f b6 50 90 01 01 0f b6 54 94 90 01 01 0f b6 48 90 01 01 c0 e2 90 01 01 0a 54 8c 90 01 01 83 c6 90 01 01 88 56 fe 83 c0 90 01 01 83 ef 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}