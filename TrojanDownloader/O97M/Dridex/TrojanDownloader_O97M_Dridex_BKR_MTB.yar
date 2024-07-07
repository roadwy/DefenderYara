
rule TrojanDownloader_O97M_Dridex_BKR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Dridex.BKR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {70 72 6f 63 65 73 73 20 63 61 6c 6c 20 63 72 65 61 74 65 20 22 6d 73 68 74 61 2e 65 78 65 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4f 72 70 45 46 78 50 70 4d 62 68 49 64 4e 47 43 42 42 45 54 58 5a 71 2e 72 74 66 } //1 process call create "mshta.exe C:\ProgramData\OrpEFxPpMbhIdNGCBBETXZq.rtf
	condition:
		((#a_01_0  & 1)*1) >=1
 
}