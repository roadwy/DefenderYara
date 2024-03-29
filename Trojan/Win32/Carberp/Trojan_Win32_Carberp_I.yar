
rule Trojan_Win32_Carberp_I{
	meta:
		description = "Trojan:Win32/Carberp.I,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 45 0a 03 00 66 c7 45 08 01 00 90 09 14 00 eb 25 90 03 05 05 6a 04 8d 45 08 8d 45 08 6a 04 50 68 80 00 00 00 68 ff ff 00 00 57 66 90 00 } //01 00 
		$a_03_1 = {c6 45 f8 63 90 02 08 66 c7 45 fb 03 00 90 00 } //01 00 
		$a_01_2 = {66 89 75 f7 c6 45 f4 73 66 89 45 f5 } //01 00 
		$a_03_3 = {66 89 95 ab f9 ff ff c6 85 a8 f9 ff ff 73 66 8b 45 90 01 01 66 89 85 a9 f9 ff ff 90 00 } //01 00 
		$a_00_4 = {73 26 73 74 61 74 70 61 73 73 3d 25 73 } //00 00  s&statpass=%s
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Carberp_I_2{
	meta:
		description = "Trojan:Win32/Carberp.I,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {74 65 50 72 c7 84 24 90 01 04 43 72 65 61 c6 84 24 90 00 } //01 00 
		$a_03_1 = {74 69 6f 6e c7 84 24 90 01 04 66 53 65 63 c7 84 24 90 00 } //01 00 
		$a_03_2 = {45 78 00 00 c7 84 24 90 01 04 6c 6c 6f 63 c7 84 24 90 01 04 75 61 6c 41 c7 84 24 90 00 } //01 00 
		$a_03_3 = {4d 65 6d 6f c7 84 24 90 01 04 63 65 73 73 c7 84 24 90 01 04 65 50 72 6f 90 00 } //01 00 
		$a_03_4 = {68 72 65 61 c7 84 24 90 01 04 47 65 74 54 c6 84 24 90 00 } //01 00 
		$a_03_5 = {79 00 00 00 c7 84 24 90 01 04 65 6d 6f 72 c7 84 24 90 01 04 65 73 73 4d 90 00 } //01 00 
		$a_03_6 = {74 65 78 74 c7 84 24 90 01 04 64 43 6f 6e c7 84 24 90 01 04 68 72 65 61 90 00 } //00 00 
		$a_00_7 = {78 1f } //01 00  ὸ
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Carberp_I_3{
	meta:
		description = "Trojan:Win32/Carberp.I,SIGNATURE_TYPE_PEHSTR_EXT,09 00 08 00 09 00 00 04 00 "
		
	strings :
		$a_01_0 = {73 65 72 76 65 72 2d 25 73 2e 67 6f 6f 67 6c 65 73 65 61 72 63 68 72 65 70 6f 72 74 2e 63 6f 6d 3a } //04 00  server-%s.googlesearchreport.com:
		$a_01_1 = {2f 73 74 61 74 3f 75 70 74 69 6d 65 3d 25 64 26 64 6f 77 6e 6c 69 6e 6b 3d 25 64 26 75 70 6c 69 6e 6b 3d 25 64 26 69 64 3d 25 73 26 73 74 61 74 70 61 73 73 3d 25 73 } //01 00  /stat?uptime=%d&downlink=%d&uplink=%d&id=%s&statpass=%s
		$a_01_2 = {26 67 75 69 64 3d 25 73 26 63 6f 6d 6d 65 6e 74 3d 25 73 26 70 3d 25 64 26 73 3d 25 73 } //02 00  &guid=%s&comment=%s&p=%d&s=%s
		$a_01_3 = {4d 70 36 63 33 59 67 75 6b 78 32 39 47 62 44 6b 5f 65 78 69 74 } //02 00  Mp6c3Ygukx29GbDk_exit
		$a_01_4 = {83 c3 03 c6 43 fd 25 88 d0 c0 e8 04 0f b6 c0 8a 80 } //01 00 
		$a_01_5 = {73 65 72 76 65 72 2d 25 73 2e 6f 31 32 39 35 35 72 65 70 73 2e 63 6f 6d 3a } //01 00  server-%s.o12955reps.com:
		$a_01_6 = {2c 73 65 72 76 65 72 2d 25 73 2e 75 70 64 6d 61 6b 65 72 2e 63 6f 6d 3a } //01 00  ,server-%s.updmaker.com:
		$a_01_7 = {73 65 72 76 65 72 2d 25 73 2e 67 67 6c 65 72 72 2e 63 6f 6d 3a } //01 00  server-%s.gglerr.com:
		$a_01_8 = {25 73 2e 74 6f 6f 6c 67 6f 74 2e 63 6f 6d 3a } //00 00  %s.toolgot.com:
		$a_00_9 = {7e 15 00 } //00 21 
	condition:
		any of ($a_*)
 
}