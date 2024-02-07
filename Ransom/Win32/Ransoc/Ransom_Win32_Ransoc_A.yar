
rule Ransom_Win32_Ransoc_A{
	meta:
		description = "Ransom:Win32/Ransoc.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 08 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 54 24 04 8b ca 83 e1 03 03 c9 b8 90 00 00 00 d3 f8 c1 ea 02 8d 0c 52 83 e0 03 03 c1 } //05 00 
		$a_01_1 = {8d 0c c5 05 00 00 00 b8 ab aa aa aa f7 e1 8b c2 c1 e8 02 83 7c 24 08 00 74 0a 83 c0 03 c1 e8 02 03 c0 03 c0 } //05 00 
		$a_01_2 = {c7 04 24 77 18 06 60 c7 44 24 04 76 03 05 79 c7 44 24 08 46 4e 7a 07 c7 44 24 0c 4b 4d 04 49 c7 44 24 10 78 47 4f 5a c7 44 24 14 33 48 5b 71 c7 44 24 18 54 4c 94 8d c7 44 24 1c 4a 01 51 64 66 c7 44 24 20 09 0a c6 44 24 22 00 } //01 00 
		$a_00_3 = {31 32 37 2e 30 2e 30 2e 31 3a 25 75 2f 73 70 6c 61 73 68 3f 63 74 72 6c 3d 25 75 26 66 3d 31 26 69 64 3d 25 73 } //01 00  127.0.0.1:%u/splash?ctrl=%u&f=1&id=%s
		$a_00_4 = {69 70 69 6e 66 6f 5f 69 6f 5f 67 65 6f } //01 00  ipinfo_io_geo
		$a_00_5 = {61 70 69 2e 69 70 69 66 79 2e 6f 72 67 } //01 00  api.ipify.org
		$a_00_6 = {6c 69 6e 6b 65 64 69 6e 2e 63 6f 6d } //01 00  linkedin.com
		$a_01_7 = {25 73 5c 73 68 61 72 65 64 2e 78 6d 6c } //00 00  %s\shared.xml
		$a_00_8 = {5d 04 00 00 ae 94 03 80 } //5c 35 
	condition:
		any of ($a_*)
 
}