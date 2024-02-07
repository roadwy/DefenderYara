
rule TrojanDownloader_O97M_Obfuse_ALA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.ALA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {32 33 61 63 65 66 69 6e 6f 70 72 73 74 75 78 79 62 63 64 65 69 6c 6f 70 73 75 79 } //01 00  23acefinoprstuxybcdeilopsuy
		$a_01_1 = {63 68 72 35 30 63 68 72 34 38 63 68 72 34 38 64 69 6d 77 73 68 73 68 65 6c 6c 61 73 6f 62 6a 65 63 74 64 69 6d 73 70 65 63 69 61 6c 70 61 74 68 61 73 73 74 72 69 6e 67 73 65 74 77 73 68 73 68 65 6c 6c 63 72 65 61 74 65 6f 62 6a 65 63 74 77 73 63 72 69 70 74 73 68 65 6c 6c 73 70 65 63 69 61 6c 70 61 74 68 } //01 00  chr50chr48chr48dimwshshellasobjectdimspecialpathasstringsetwshshellcreateobjectwscriptshellspecialpath
		$a_01_2 = {69 66 73 74 61 74 75 73 32 30 30 74 68 65 6e 73 65 74 63 72 65 61 74 65 6f 62 6a 65 63 74 61 64 6f 64 62 73 74 72 65 61 6d 6f 70 65 6e 74 79 70 65 77 72 69 74 65 73 61 76 65 74 6f 66 69 6c 65 63 6c 6f 73 65 65 6e 64 69 66 6f 70 65 6e 65 6e 64 73 75 62 } //01 00  ifstatus200thensetcreateobjectadodbstreamopentypewritesavetofilecloseendifopenendsub
		$a_01_3 = {63 72 65 61 74 65 6f 62 6a 65 63 74 73 68 65 6c 6c 61 70 70 6c 69 63 61 74 69 6f 6e 73 70 65 63 69 61 6c 70 61 74 68 67 7a 77 66 68 6f 70 65 6e 67 65 74 68 77 77 77 } //00 00  createobjectshellapplicationspecialpathgzwfhopengethwww
	condition:
		any of ($a_*)
 
}