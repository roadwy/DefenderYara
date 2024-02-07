
rule Trojan_Win32_RedLineStealer_VZ_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.VZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {92 24 83 c4 04 f7 e6 8b c6 2b c2 d1 e8 03 c2 c1 e8 02 8d 0c c5 90 01 04 2b c8 8b c6 2b c1 8a 80 90 01 04 30 04 1e 46 ff 07 3b f5 72 c4 90 00 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00  VirtualProtect
	condition:
		any of ($a_*)
 
}