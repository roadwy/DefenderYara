
rule Trojan_Win32_Tracur_AF{
	meta:
		description = "Trojan:Win32/Tracur.AF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {3d 2e 6a 70 67 74 } //01 00  =.jpgt
		$a_01_1 = {8b 45 08 8d 40 18 50 } //01 00 
		$a_03_2 = {8b 45 0c ff 10 83 c4 90 09 02 00 54 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}