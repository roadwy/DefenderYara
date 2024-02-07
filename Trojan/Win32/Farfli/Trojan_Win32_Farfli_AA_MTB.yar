
rule Trojan_Win32_Farfli_AA_MTB{
	meta:
		description = "Trojan:Win32/Farfli.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b 55 08 03 55 0c 33 c0 8a 42 ff 89 45 e8 8b 4d e8 c1 e9 05 8b 55 ec c1 e2 02 33 ca 8b 45 ec c1 e8 03 8b 55 e8 c1 e2 04 33 c2 03 c8 8b 45 f4 33 45 ec 8b 55 f8 83 e2 03 33 55 f0 8b 75 10 8b 14 96 33 55 e8 03 c2 33 c8 8b 45 08 8a 10 2a d1 8b 45 08 88 10 8b 4d 08 33 d2 8a 11 89 55 ec 8b 45 f4 05 47 86 c8 61 89 45 f4 8b 4d fc 83 e9 01 89 4d fc 83 7d fc 00 0f 85 } //01 00 
		$a_01_1 = {77 77 77 2e 78 79 39 39 39 2e 63 6f 6d } //01 00  www.xy999.com
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00  URLDownloadToFileA
	condition:
		any of ($a_*)
 
}