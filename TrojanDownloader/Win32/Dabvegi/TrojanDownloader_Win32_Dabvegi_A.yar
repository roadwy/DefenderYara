
rule TrojanDownloader_Win32_Dabvegi_A{
	meta:
		description = "TrojanDownloader:Win32/Dabvegi.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 6f 61 64 44 6f 77 6e 6c 6f 61 64 65 72 00 } //01 00 
		$a_01_1 = {43 68 61 6d 61 46 69 72 65 77 61 6c 6c 00 } //01 00  桃浡䙡物睥污l
		$a_01_2 = {43 72 54 78 74 00 } //01 00  牃硔t
		$a_01_3 = {4d 79 73 66 78 00 } //00 00  祍晳x
	condition:
		any of ($a_*)
 
}