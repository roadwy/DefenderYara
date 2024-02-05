
rule Trojan_Win32_AresLdrShell_LK_MTB{
	meta:
		description = "Trojan:Win32/AresLdrShell.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 04 68 00 30 00 00 55 90 01 01 ff 54 90 00 } //01 00 
		$a_03_1 = {6a 04 68 00 30 00 00 55 ff 90 01 02 ff 54 90 00 } //01 00 
		$a_01_2 = {8b 42 04 03 47 08 8b 4a fc 03 cb 8a 04 30 88 04 31 46 3b 32 72 ea } //00 00 
	condition:
		any of ($a_*)
 
}