
rule TrojanDownloader_Win32_Genome_AT{
	meta:
		description = "TrojanDownloader:Win32/Genome.AT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 4d d4 ff 15 90 01 02 40 00 66 c7 45 c0 94 11 ba 90 01 02 40 00 8d 4d d8 ff 15 90 01 02 40 00 8d 90 01 01 bc 90 00 } //01 00 
		$a_01_1 = {75 70 64 61 74 65 2e 65 78 65 3f 6d 6f 64 65 3d } //01 00 
		$a_01_2 = {64 6c 69 6e 6b 64 64 6e 73 2e 63 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}