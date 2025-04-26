
rule TrojanDownloader_BAT_Banload_S{
	meta:
		description = "TrojanDownloader:BAT/Banload.S,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {5c 00 69 00 6d 00 61 00 64 00 77 00 6d 00 2e 00 65 00 78 00 65 00 [0-0a] 68 00 74 00 74 00 70 00 } //2
		$a_01_1 = {2e 00 76 00 6d 00 70 00 2e 00 73 00 63 00 72 00 } //1 .vmp.scr
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}