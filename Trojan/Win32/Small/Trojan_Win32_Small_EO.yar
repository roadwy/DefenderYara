
rule Trojan_Win32_Small_EO{
	meta:
		description = "Trojan:Win32/Small.EO,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 6c 45 78 65 } //01 00  hlExe
		$a_01_1 = {68 53 68 65 6c } //02 00  hShel
		$a_01_2 = {50 58 68 65 72 50 72 } //02 00  PXherPr
		$a_01_3 = {50 58 68 62 75 67 67 } //00 00  PXhbugg
	condition:
		any of ($a_*)
 
}