
rule TrojanDownloader_Win32_Cekar_gen_C{
	meta:
		description = "TrojanDownloader:Win32/Cekar.gen!C,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {eb f1 55 53 56 57 8b e8 03 40 3c 8b 78 78 03 fd 8b 77 20 03 f5 33 d2 8b 06 03 c5 81 38 47 65 74 50 75 32 81 78 04 72 6f 63 41 75 29 81 78 08 64 64 72 65 75 20 66 81 78 0c 73 73 75 18 } //00 00 
	condition:
		any of ($a_*)
 
}