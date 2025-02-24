
rule TrojanDownloader_O97M_Obfuse_RVCJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVCJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {62 76 75 6b 77 78 69 64 30 67 69 6d 68 30 64 68 61 36 6c 79 39 73 62 32 78 22 65 6e 63 6f 64 65 64 73 74 72 69 6e 67 3d 65 6e 63 6f 64 65 64 73 74 72 69 6e 67 26 22 74 79 77 71 75 62 67 6c 32 7a 77 6a 73 62 32 63 7a 6e 6a 75 75 79 32 39 74 22 65 6e 63 6f 64 65 64 73 74 72 69 6e 67 3d 65 6e 63 6f 64 65 64 73 74 72 69 6e 67 26 22 6c 33 6a 68 62 6e 6e 76 62 78 64 68 63 6d 75 75 64 68 68 30 69 69 61 6e 69 22 } //1 bvukwxid0gimh0dha6ly9sb2x"encodedstring=encodedstring&"tywqubgl2zwjsb2cznjuuy29t"encodedstring=encodedstring&"l3jhbnnvbxdhcmuudhh0iiani"
		$a_01_1 = {2e 72 75 6e 76 62 63 6f 6d 70 2e 6e 61 6d 65 26 22 2e 64 6f 77 6e 6c 6f 61 64 74 77 6f 66 69 6c 65 73 66 72 6f 6d 75 72 6c 22 65 6e 64 73 75 62 66 75 6e 63 74 69 6f 6e } //1 .runvbcomp.name&".downloadtwofilesfromurl"endsubfunction
		$a_01_2 = {64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 } //1 document_open()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}