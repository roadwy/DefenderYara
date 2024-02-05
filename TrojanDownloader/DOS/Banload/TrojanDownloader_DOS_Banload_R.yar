
rule TrojanDownloader_DOS_Banload_R{
	meta:
		description = "TrojanDownloader:DOS/Banload.R,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {51 00 37 00 48 00 71 00 53 00 33 00 65 00 6c 00 42 00 73 00 4f 00 6b 00 4f 00 73 00 6d 00 6b 00 52 00 37 00 61 00 6c 00 51 00 4e 00 48 00 62 00 52 00 4e 00 43 00 6c 00 43 00 } //01 00 
		$a_00_1 = {83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 8b c8 8b 45 f0 99 f7 f9 89 55 f0 b9 00 01 00 00 8b c3 99 f7 f9 } //00 00 
	condition:
		any of ($a_*)
 
}