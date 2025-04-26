
rule TrojanDownloader_O97M_Donoff_PV{
	meta:
		description = "TrojanDownloader:O97M/Donoff.PV,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {22 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 22 20 26 20 5f } //1 "DownloadFile" & _
		$a_01_1 = {6f 6c 75 79 61 6d 61 63 68 69 6e 65 2e 78 79 7a } //1 oluyamachine.xyz
		$a_01_2 = {27 2c 27 25 74 65 6d 70 25 } //1 ','%temp%
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}