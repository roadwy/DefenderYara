
rule TrojanDownloader_BAT_Banload_U{
	meta:
		description = "TrojanDownloader:BAT/Banload.U,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6c 69 6e 6b 64 61 6b 6c } //1 linkdakl
		$a_03_1 = {6e 6f 6d 65 64 (6f 7a 69 70|61 6b 6c) } //1
		$a_01_2 = {75 00 6e 00 7a 00 69 00 70 00 2e 00 65 00 78 00 65 00 } //1 unzip.exe
		$a_01_3 = {42 61 6e 6b 73 5c 4c 6f 61 64 65 72 73 } //1 Banks\Loaders
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}