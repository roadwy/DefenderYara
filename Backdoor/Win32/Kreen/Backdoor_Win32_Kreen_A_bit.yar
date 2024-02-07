
rule Backdoor_Win32_Kreen_A_bit{
	meta:
		description = "Backdoor:Win32/Kreen.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {66 8b 08 83 c0 02 66 85 c9 75 f5 2b c2 d1 f8 74 3a 56 8b 75 0c 56 68 90 01 04 57 e8 90 01 04 66 83 36 90 01 01 8b 45 08 83 c4 0c 83 c6 02 83 c3 02 83 c7 04 8d 50 02 66 8b 08 83 c0 02 66 85 c9 75 f5 2b c2 d1 f8 3b d8 72 cb 90 00 } //02 00 
		$a_01_1 = {33 c0 b1 5c 2a c8 30 8c 05 f8 fe ff ff 40 83 f8 5c 72 ef } //01 00 
		$a_01_2 = {5c 00 66 00 69 00 6c 00 65 00 63 00 66 00 67 00 5f 00 74 00 65 00 6d 00 70 00 2e 00 64 00 61 00 74 00 } //00 00  \filecfg_temp.dat
		$a_00_3 = {5d 04 00 } //00 bc 
	condition:
		any of ($a_*)
 
}