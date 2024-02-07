
rule Virus_Win32_Jadtre_gen_A{
	meta:
		description = "Virus:Win32/Jadtre.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b ff 55 a1 90 01 04 83 c0 03 ff e0 90 00 } //01 00 
		$a_03_1 = {83 c4 10 0f be 05 90 01 04 83 f8 92 75 16 90 00 } //02 00 
		$a_03_2 = {c7 40 24 20 00 00 e0 8b 45 90 01 01 8b 0d 90 01 04 66 8b 09 66 89 48 22 90 00 } //01 00 
		$a_01_3 = {5c 5c 2e 5c 70 69 70 65 5c 39 36 44 42 41 32 34 39 2d 45 38 38 45 2d 34 63 34 37 2d 39 38 44 43 2d 45 31 38 45 36 45 33 45 33 45 35 41 } //00 00  \\.\pipe\96DBA249-E88E-4c47-98DC-E18E6E3E3E5A
	condition:
		any of ($a_*)
 
}