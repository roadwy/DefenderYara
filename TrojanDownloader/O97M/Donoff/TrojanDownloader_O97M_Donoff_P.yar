
rule TrojanDownloader_O97M_Donoff_P{
	meta:
		description = "TrojanDownloader:O97M/Donoff.P,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {52 77 74 70 42 6f 71 6e } //1 RwtpBoqn
		$a_00_1 = {53 75 6b 6c 4e 7a 4d 76 64 6d 4b 64 48 68 79 4b 72 48 76 47 76 63 42 42 } //1 SuklNzMvdmKdHhyKrHvGvcBB
		$a_00_2 = {68 50 4d 51 51 70 54 4e 6f 79 64 76 54 6d 6e 41 4f 6c 7a 42 51 5a 53 4c 47 48 52 6c 65 4a 4f } //1 hPMQQpTNoydvTmnAOlzBQZSLGHRleJO
		$a_00_3 = {4f 47 55 58 45 53 78 47 4c 72 4a 69 48 6b 78 61 2c } //1 OGUXESxGLrJiHkxa,
		$a_00_4 = {71 65 4f 74 7a 42 4a 65 6d 52 74 77 6e 57 53 56 71 } //1 qeOtzBJemRtwnWSVq
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}