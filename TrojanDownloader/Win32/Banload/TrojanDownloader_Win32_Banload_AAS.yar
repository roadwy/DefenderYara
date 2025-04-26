
rule TrojanDownloader_Win32_Banload_AAS{
	meta:
		description = "TrojanDownloader:Win32/Banload.AAS,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {62 74 6e 69 6e 78 43 6c 69 63 6b } //2 btninxClick
		$a_01_1 = {62 74 6e 64 6f 78 43 6c 69 63 6b } //2 btndoxClick
		$a_01_2 = {62 74 6e 73 65 78 43 6c 69 63 6b } //2 btnsexClick
		$a_01_3 = {75 6e 69 74 63 72 69 70 74 } //1 unitcript
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}