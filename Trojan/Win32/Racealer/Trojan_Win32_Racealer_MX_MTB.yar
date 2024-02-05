
rule Trojan_Win32_Racealer_MX_MTB{
	meta:
		description = "Trojan:Win32/Racealer.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b d6 c1 ea 05 03 54 24 90 01 01 89 54 24 24 3d 31 09 00 00 90 00 } //01 00 
		$a_02_1 = {33 c1 2b f0 e8 90 01 04 8b d6 8b c8 d3 e2 89 6c 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}