
rule TrojanDownloader_O97M_Malgent_KSH_MSR{
	meta:
		description = "TrojanDownloader:O97M/Malgent.KSH!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {61 72 67 75 6d 65 6e 74 73 3d 22 68 74 74 70 73 3a 2f 2f 64 33 37 32 37 6d 68 65 76 74 6b 32 6e 34 2e 63 6c 6f 75 64 66 72 6f 6e 74 2e 6e 65 74 2f 73 72 76 2d 73 74 67 2d 61 67 65 6e 74 } //01 00 
		$a_00_1 = {6d 63 61 66 65 65 61 76 75 70 64 61 74 65 74 61 73 6b } //00 00 
	condition:
		any of ($a_*)
 
}