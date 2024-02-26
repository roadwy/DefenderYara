
rule Trojan_Win32_HeavensGateShell_YAA_MTB{
	meta:
		description = "Trojan:Win32/HeavensGateShell.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4e 20 8b 46 28 31 04 11 83 c2 04 3b 56 24 72 ef } //00 00 
	condition:
		any of ($a_*)
 
}