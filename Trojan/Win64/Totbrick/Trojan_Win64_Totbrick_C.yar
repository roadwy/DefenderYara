
rule Trojan_Win64_Totbrick_C{
	meta:
		description = "Trojan:Win64/Totbrick.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {80 7c 24 50 71 8b fb 74 4e 85 c0 75 4a 83 ff 64 7d 45 } //01 00 
		$a_01_1 = {41 ff c0 80 38 00 75 f4 41 8d 40 ff 3d 02 01 00 00 77 12 } //01 00 
		$a_01_2 = {5c 5c 2e 5c 70 69 70 65 5c 70 69 64 70 6c 61 63 65 73 6f 6d 65 70 69 70 65 } //00 00  \\.\pipe\pidplacesomepipe
	condition:
		any of ($a_*)
 
}