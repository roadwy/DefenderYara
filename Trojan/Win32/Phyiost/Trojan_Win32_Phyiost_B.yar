
rule Trojan_Win32_Phyiost_B{
	meta:
		description = "Trojan:Win32/Phyiost.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 66 63 5f 6f 73 2e 64 6c 6c } //01 00 
		$a_00_1 = {63 6d 64 20 2f 63 20 6e 65 74 20 73 74 61 72 74 20 73 72 73 65 72 76 69 63 } //01 00 
		$a_00_2 = {63 6d 64 20 2f 63 20 72 65 6e 20 } //01 00 
		$a_02_3 = {c7 07 64 6c 6c 63 83 c7 04 c7 07 61 63 68 65 83 c7 04 c7 07 5c 73 72 73 83 c7 04 c7 07 76 63 2e 64 83 c7 04 66 c7 07 6c 6c 83 c7 02 c6 07 00 6a 00 68 90 01 04 e8 90 01 04 8d 3d 90 01 04 8d 35 90 01 04 b9 0b 00 00 00 f3 a4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}