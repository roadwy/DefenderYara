
rule TrojanDownloader_O97M_MalSpam_RDU_MTB{
	meta:
		description = "TrojanDownloader:O97M/MalSpam.RDU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 43 6f 6d 6d 61 6e 64 20 49 45 58 } //01 00  owershell.exe -Command IEX
		$a_00_1 = {4e 65 77 2d 4f 62 6a 65 63 74 28 27 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 27 29 } //01 00  New-Object('Net.WebClient')
		$a_00_2 = {44 6f 57 6e 6c 6f 41 64 73 54 72 49 6e 47 27 28 27 } //01 00  DoWnloAdsTrInG'('
		$a_00_3 = {68 74 27 2b 27 74 70 73 3a 2f 2f 70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 72 61 77 2f 66 41 53 77 39 77 43 5a 27 29 } //00 00  ht'+'tps://pastebin.com/raw/fASw9wCZ')
	condition:
		any of ($a_*)
 
}