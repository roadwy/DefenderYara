
rule Trojan_Win32_RedLineStealer_PE_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.PE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 44 24 18 8b 4c 24 20 8b c3 d3 e8 89 44 24 14 8b 44 24 38 01 44 24 14 8b cb c1 e1 90 01 01 03 4c 24 3c 89 15 90 01 04 33 4c 24 14 33 4c 24 18 2b f9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}