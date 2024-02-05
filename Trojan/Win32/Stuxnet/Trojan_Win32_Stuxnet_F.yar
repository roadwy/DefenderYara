
rule Trojan_Win32_Stuxnet_F{
	meta:
		description = "Trojan:Win32/Stuxnet.F,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 37 6f 74 62 78 73 78 2e 64 6c 6c } //01 00 
		$a_00_1 = {73 37 5f 67 65 74 5f 70 61 73 73 77 6f 72 64 } //01 00 
		$a_00_2 = {73 37 48 5f 73 74 61 72 74 5f 63 70 75 } //01 00 
		$a_03_3 = {8b 74 24 08 80 7e 90 01 01 00 75 05 8d 46 90 01 01 5e c3 0f b7 46 90 01 01 57 50 8d 7e 90 01 01 57 e8 90 01 04 80 66 90 01 01 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}