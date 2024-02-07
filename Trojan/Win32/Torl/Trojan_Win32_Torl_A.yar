
rule Trojan_Win32_Torl_A{
	meta:
		description = "Trojan:Win32/Torl.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 93 80 03 00 00 0f b6 92 6a 02 00 00 4a 80 ea 01 0f 92 c1 ba 90 01 04 e8 90 01 02 ff ff 8b 83 84 03 00 00 8b 80 70 02 00 00 8b 10 ff 52 14 90 00 } //01 00 
		$a_00_1 = {5c 00 75 00 73 00 65 00 72 00 70 00 72 00 6f 00 66 00 69 00 6c 00 65 00 2e 00 64 00 6c 00 6c 00 22 00 2c 00 77 00 6f 00 72 00 6b 00 } //01 00  \userprofile.dll",work
		$a_00_2 = {5c 00 66 00 69 00 72 00 65 00 66 00 6f 00 78 00 5c 00 70 00 72 00 6f 00 66 00 69 00 6c 00 65 00 73 00 2e 00 69 00 6e 00 69 00 } //00 00  \firefox\profiles.ini
	condition:
		any of ($a_*)
 
}