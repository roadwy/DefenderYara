
rule Trojan_Win64_Bampeass_B{
	meta:
		description = "Trojan:Win64/Bampeass.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 41 43 4d 65 20 69 6e 6a 65 63 74 65 64 2c 20 48 69 62 69 6b 69 20 61 74 20 79 6f 75 72 20 73 65 72 76 69 63 65 2e } //01 00  UACMe injected, Hibiki at your service.
		$a_01_1 = {75 63 6d 4c 6f 61 64 43 61 6c 6c 62 61 63 6b 2c 20 64 6c 6c 20 6c 6f 61 64 20 25 77 73 2c 20 44 6c 6c 42 61 73 65 20 3d 20 25 70 } //02 00  ucmLoadCallback, dll load %ws, DllBase = %p
		$a_01_2 = {ba 63 00 00 00 48 2b f8 90 0f b7 4c 07 02 48 8d 40 02 0f b7 d1 66 85 c9 75 ef 48 8d 44 24 70 48 8d 0d a3 1c 00 00 45 33 c9 48 89 44 24 48 48 8d 45 90 45 33 c0 48 89 44 24 40 48 8d 45 00 33 d2 48 89 44 24 38 48 89 5c 24 30 89 5c 24 28 89 5c 24 20 ff 15 } //00 00 
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}