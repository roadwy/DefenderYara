
rule Trojan_Win32_Delf_MK{
	meta:
		description = "Trojan:Win32/Delf.MK,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {74 61 73 6b 6d 67 72 73 90 02 08 53 74 61 72 74 90 00 } //01 00 
		$a_01_1 = {3a 61 64 65 6c } //01 00  :adel
		$a_01_2 = {63 68 6f 69 63 65 20 2f 74 20 35 20 2f 64 20 79 } //00 00  choice /t 5 /d y
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}