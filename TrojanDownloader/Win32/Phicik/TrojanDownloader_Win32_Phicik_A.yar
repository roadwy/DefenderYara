
rule TrojanDownloader_Win32_Phicik_A{
	meta:
		description = "TrojanDownloader:Win32/Phicik.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {57 69 6e 64 6f 77 73 20 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 90 02 04 48 44 69 64 90 02 04 25 75 2e 25 75 2e 25 75 2e 25 75 7c 90 02 10 25 73 7c 25 73 7c 25 73 7c 25 73 7c 25 73 7c 25 73 90 02 04 50 4f 53 54 90 02 04 64 3d 25 73 26 69 3d 25 73 90 00 } //01 00 
		$a_01_1 = {42 41 53 45 57 4e 44 } //01 00 
		$a_00_2 = {44 65 6c 65 74 65 55 72 6c 43 61 63 68 65 45 6e 74 72 79 } //00 00 
	condition:
		any of ($a_*)
 
}