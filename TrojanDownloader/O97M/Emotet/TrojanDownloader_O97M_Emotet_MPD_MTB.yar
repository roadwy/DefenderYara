
rule TrojanDownloader_O97M_Emotet_MPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.MPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 22 26 22 65 67 22 26 22 73 76 22 26 22 72 33 22 26 22 32 2e 65 78 65 [0-0a] 53 79 73 22 26 22 57 6f 77 22 26 22 36 34 5c [0-03] 5c 57 22 26 22 69 22 26 22 6e 64 6f 22 26 22 77 73 [0-2f] 5c 64 66 65 62 2e 73 65 73 [0-06] 5c 64 66 65 62 2e 73 65 73 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}