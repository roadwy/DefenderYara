
rule TrojanDownloader_O97M_Qakbot_PDM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.PDM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 4d 65 72 74 69 6f 5c 4a 75 61 64 6f 73 74 5c 4b 69 65 6e 73 65 2e 6f 6f 6f 6f 6f 6f 6f 6f 6f 6f 6f 6f 6f 6f 6f 6f 6f 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 } //1 C:\Mertio\Juadost\Kiense.ooooooooooooooooocccccccccccccccccccccccccccccccxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	condition:
		((#a_01_0  & 1)*1) >=1
 
}