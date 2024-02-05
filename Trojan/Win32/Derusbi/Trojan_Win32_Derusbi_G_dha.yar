
rule Trojan_Win32_Derusbi_G_dha{
	meta:
		description = "Trojan:Win32/Derusbi.G!dha,SIGNATURE_TYPE_PEHSTR_EXT,2c 01 2c 01 04 00 00 64 00 "
		
	strings :
		$a_00_0 = {39 00 33 00 31 00 34 00 34 00 45 00 42 00 30 00 2d 00 38 00 45 00 33 00 45 00 2d 00 34 00 35 00 39 00 31 00 2d 00 42 00 33 00 30 00 37 00 2d 00 38 00 45 00 45 00 42 00 46 00 45 00 37 00 44 00 42 00 32 00 38 00 46 00 } //64 00 
		$a_02_1 = {73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 90 02 10 2d 25 73 2d 25 30 33 64 90 02 10 2d 25 30 33 64 90 00 } //64 00 
		$a_00_2 = {5a 77 4c 6f 61 64 44 72 69 76 65 72 } //64 00 
		$a_00_3 = {5a 00 68 00 75 00 44 00 6f 00 6e 00 67 00 46 00 61 00 6e 00 67 00 59 00 75 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}