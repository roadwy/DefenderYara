
rule VirTool_Win64_Alanloader_A{
	meta:
		description = "VirTool:Win64/Alanloader.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {48 33 db ac 84 c0 90 01 02 c1 cf 13 3c 61 48 0f 4d da 2a c3 48 0f b6 c0 03 f8 90 00 } //1
		$a_02_1 = {48 0f b7 0b 48 03 f9 fd 48 33 c0 b0 5c 48 8b f7 f2 ae fc 90 01 03 48 83 c7 02 48 2b f7 48 8b d6 48 8b cf 90 00 } //1
		$a_00_2 = {8b 36 48 03 34 24 48 33 c0 48 8b fe b9 12 05 00 00 fc f2 ae 48 2b fe 48 ff cf 48 8b ce 48 8b d7 } //1
		$a_00_3 = {49 c7 c1 04 00 00 00 49 c7 c0 00 30 00 00 49 8b d7 48 33 c9 48 83 ec 28 ff d0 48 83 c4 28 48 85 c0 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}