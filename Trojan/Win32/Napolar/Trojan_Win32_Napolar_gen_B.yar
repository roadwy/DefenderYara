
rule Trojan_Win32_Napolar_gen_B{
	meta:
		description = "Trojan:Win32/Napolar.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 3a 28 4d 4c 3b 3b 4e 57 3b 3b 3b 4c 57 29 44 3a 28 41 3b 3b 30 78 31 32 30 31 39 62 3b 3b 3b 57 44 29 } //01 00  S:(ML;;NW;;;LW)D:(A;;0x12019b;;;WD)
		$a_81_1 = {76 3d 25 64 2e 25 64 26 75 3d 25 73 26 63 3d 25 73 26 73 3d 25 73 26 77 3d 25 64 2e } //01 00  v=%d.%d&u=%s&c=%s&s=%s&w=%d.
		$a_01_2 = {70 3d 25 73 26 68 3d 25 73 26 75 3d 25 73 26 73 3d 25 30 38 6c 58 } //01 00  p=%s&h=%s&u=%s&s=%08lX
		$a_03_3 = {66 74 70 3a 2f 2f 25 64 2e 25 64 2e 25 64 2e 25 64 00 2e 72 64 61 74 61 00 2e 74 65 78 74 90 02 04 53 53 4c 90 02 04 53 4f 4c 41 52 90 00 } //01 00 
		$a_01_4 = {5c 5c 2e 5c 70 69 70 65 5c 6e 61 70 53 6f 6c 61 72 } //00 00  \\.\pipe\napSolar
		$a_00_5 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Napolar_gen_B_2{
	meta:
		description = "Trojan:Win32/Napolar.gen!B!!Napolar,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 3a 28 4d 4c 3b 3b 4e 57 3b 3b 3b 4c 57 29 44 3a 28 41 3b 3b 30 78 31 32 30 31 39 62 3b 3b 3b 57 44 29 } //01 00  S:(ML;;NW;;;LW)D:(A;;0x12019b;;;WD)
		$a_81_1 = {76 3d 25 64 2e 25 64 26 75 3d 25 73 26 63 3d 25 73 26 73 3d 25 73 26 77 3d 25 64 2e } //01 00  v=%d.%d&u=%s&c=%s&s=%s&w=%d.
		$a_01_2 = {70 3d 25 73 26 68 3d 25 73 26 75 3d 25 73 26 73 3d 25 30 38 6c 58 } //01 00  p=%s&h=%s&u=%s&s=%08lX
		$a_03_3 = {66 74 70 3a 2f 2f 25 64 2e 25 64 2e 25 64 2e 25 64 00 2e 72 64 61 74 61 00 2e 74 65 78 74 90 02 04 53 53 4c 90 02 04 53 4f 4c 41 52 90 00 } //01 00 
		$a_01_4 = {5c 5c 2e 5c 70 69 70 65 5c 6e 61 70 53 6f 6c 61 72 } //05 00  \\.\pipe\napSolar
	condition:
		any of ($a_*)
 
}