
rule Trojan_Win32_Startpage_RI_dll{
	meta:
		description = "Trojan:Win32/Startpage.RI!dll,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 04 00 "
		
	strings :
		$a_02_0 = {99 f7 7d 0c 8b 90 01 01 08 90 01 03 32 90 01 01 32 45 14 90 00 } //01 00 
		$a_00_1 = {76 d5 83 f8 07 73 d0 } //01 00 
		$a_02_2 = {85 c0 74 ed 83 7d 90 01 01 02 75 e7 8b 40 04 33 90 01 01 66 83 38 2d 0f 94 90 00 } //01 00 
		$a_00_3 = {46 65 78 70 6c 6f 72 65 72 2e 65 78 } //01 00 
		$a_00_4 = {3a 2f 2f 77 77 77 2e 25 73 2f 3f 39 } //01 00 
		$a_00_5 = {57 49 4e 44 4f 57 53 5c 6b 73 77 65 62 73 68 69 65 6c 64 2e 64 6c } //01 00 
		$a_00_6 = {67 6f 32 30 30 30 2e 63 } //00 00 
	condition:
		any of ($a_*)
 
}