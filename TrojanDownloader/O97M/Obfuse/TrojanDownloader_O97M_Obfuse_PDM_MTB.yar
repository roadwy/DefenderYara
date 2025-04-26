
rule TrojanDownloader_O97M_Obfuse_PDM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PDM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 63 68 72 28 35 30 29 2b 63 68 72 28 34 38 29 2b 63 68 72 28 34 38 29 } //1 =chr(50)+chr(48)+chr(48)
		$a_01_1 = {73 70 65 63 69 61 6c 70 61 74 68 3d 77 73 68 73 68 65 6c 6c 2e 73 70 65 63 69 61 6c 66 6f 6c 64 65 72 73 28 22 72 65 63 65 6e 74 22 29 } //1 specialpath=wshshell.specialfolders("recent")
		$a_01_2 = {3d 73 70 65 63 69 61 6c 70 61 74 68 2b 28 22 5c 7a 72 2e 22 29 2e 6f 70 65 6e 22 67 65 74 22 2c 28 22 68 3a 2f 2f 64 6a 6b 6d 77 2e 6d 2e 6c 2e 31 64 76 2e 6d 2f 34 6d 6d 7a 36 68 6b 7a 66 68 74 } //1 =specialpath+("\zr.").open"get",("h://djkmw.m.l.1dv.m/4mmz6hkzfht
		$a_01_3 = {3d 31 72 61 6e 67 65 28 22 6a 31 22 29 2e 76 61 6c 75 65 3d 22 65 6b 6c 69 62 65 6c 67 65 79 69 61 6d 61 22 6d 73 67 62 6f 78 22 70 6c 65 61 73 65 77 61 69 74 2e 2e 2e 2e 22 72 61 6e 67 65 28 22 62 63 33 22 29 2e 76 61 6c 75 65 3d } //1 =1range("j1").value="eklibelgeyiama"msgbox"pleasewait...."range("bc3").value=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}