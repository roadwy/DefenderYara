
rule TrojanDownloader_O97M_Gootkit_D_MSR{
	meta:
		description = "TrojanDownloader:O97M/Gootkit.D!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_00_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 42 61 73 65 20 3d 20 22 31 4e 6f 72 6d 61 6c 2e 54 68 69 73 44 6f 63 75 6d 65 6e 74 22 } //5 Attribute VB_Base = "1Normal.ThisDocument"
		$a_02_1 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 [0-10] 20 90 0f 03 00 [0-10] 20 90 0f 03 00 [0-10] 20 90 0f 03 00 [0-10] 20 90 0f 03 00 [0-10] 20 90 0f 03 00 [0-10] 20 90 0f 03 00 [0-10] 20 90 0f 03 00 } //20
	condition:
		((#a_00_0  & 1)*5+(#a_02_1  & 1)*20) >=25
 
}