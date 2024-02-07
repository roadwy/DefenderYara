
rule Trojan_Win32_Alureon_EO{
	meta:
		description = "Trojan:Win32/Alureon.EO,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {04 37 13 c3 cd 8b 90 01 01 03 90 01 01 85 90 09 05 00 89 90 01 01 08 c7 90 00 } //01 00 
		$a_03_1 = {51 6a 05 6a 01 53 ff 15 90 01 04 3b c7 74 90 00 } //01 00 
		$a_01_2 = {6c 64 72 5f 64 6c 6c } //01 00  ldr_dll
	condition:
		any of ($a_*)
 
}