
rule TrojanDownloader_O97M_Obfuse_PDD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PDD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {3d 63 68 72 28 35 30 29 2b 63 68 72 28 34 38 29 2b 63 68 72 28 34 38 29 73 65 74 77 73 68 73 68 65 6c 6c 3d } //1 =chr(50)+chr(48)+chr(48)setwshshell=
		$a_01_1 = {3d 73 70 65 63 69 61 6c 70 61 74 68 2b 28 22 5c 6d 68 6b 2e 22 29 2e 6f 70 65 6e } //1 =specialpath+("\mhk.").open
		$a_01_2 = {3d 77 73 68 73 68 65 6c 6c 2e 73 70 65 63 69 61 6c 66 6f 6c 64 65 72 73 28 22 72 65 63 65 66 76 64 7a 62 22 29 } //1 =wshshell.specialfolders("recefvdzb")
		$a_01_3 = {3d 67 65 74 64 65 73 6b 74 6f 70 2b 68 75 67 75 68 68 6a 67 68 6a 67 74 72 6f 69 6e 28 6a 68 62 68 65 66 76 65 72 66 64 2e 6f 69 6e 29 6d 6f 69 6a 68 69 75 66 2e 6f 70 65 6e 22 69 69 75 6b 79 22 } //1 =getdesktop+huguhhjghjgtroin(jhbhefverfd.oin)moijhiuf.open"iiuky"
		$a_01_4 = {2e 76 61 6c 75 65 3d 22 3c 3c 6f 6b 2e 2e 2e 2e 2e 2e 6f 6b 3e 3e 22 6d 73 67 62 6f 78 22 3c 3c 6f 6b 2e 2e 2e 2e 2e 2e 6f 6b 3e 3e } //1 .value="<<ok......ok>>"msgbox"<<ok......ok>>
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}