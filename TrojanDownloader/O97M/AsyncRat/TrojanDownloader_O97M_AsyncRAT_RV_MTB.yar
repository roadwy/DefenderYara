
rule TrojanDownloader_O97M_AsyncRAT_RV_MTB{
	meta:
		description = "TrojanDownloader:O97M/AsyncRAT.RV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 74 70 3a 2f 2f 31 33 39 2e 31 36 32 2e 32 32 2e 33 35 2f 31 2e 62 61 74 } //1 ttp://139.162.22.35/1.bat
		$a_01_1 = {63 61 6c 6c 73 68 65 6c 6c 28 73 74 72 66 69 6c 65 2c 76 62 6e 6f 72 6d 61 6c 66 6f 63 75 73 29 65 6c 73 65 65 6e 64 69 66 65 6e 64 73 75 62 } //1 callshell(strfile,vbnormalfocus)elseendifendsub
		$a_01_2 = {73 75 62 61 75 74 6f 6f 70 65 6e 28 29 } //1 subautoopen()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}