
rule Trojan_Win32_Sloddat_A{
	meta:
		description = "Trojan:Win32/Sloddat.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 05 00 00 00 e8 fe a1 fd ff 83 f8 05 0f 87 07 01 00 00 ff 24 85 62 8e 42 00 } //01 00 
		$a_01_1 = {b8 df 00 00 00 e8 36 04 fe ff 3d df 00 00 00 0f 87 25 1e 00 00 ff 24 85 2c 2c 42 00 } //01 00 
		$a_01_2 = {c1 e2 02 52 ba 77 00 00 00 59 2b d1 88 50 01 c6 00 01 8d 95 4c fd ff ff 8d 85 50 fd ff ff b1 02 } //02 00 
		$a_01_3 = {72 65 74 2c 64 2b 77 6f 32 72 68 63 64 2b 71 5f 69 65 6e 5e 00 } //00 00 
		$a_00_4 = {80 } //10 00 
	condition:
		any of ($a_*)
 
}