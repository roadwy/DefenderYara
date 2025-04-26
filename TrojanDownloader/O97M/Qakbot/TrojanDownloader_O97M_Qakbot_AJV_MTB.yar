
rule TrojanDownloader_O97M_Qakbot_AJV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.AJV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f [0-04] 77 77 77 2e 74 68 65 6a 72 67 73 2e 63 6f 6d 2f 70 6c 62 66 79 72 70 71 69 6f 2f [0-04] 6a 70 67 } //1
		$a_01_1 = {43 3a 5c 46 6c 6f 70 65 72 73 5c 46 6c 6f 70 65 72 73 32 5c 42 69 6c 6f 72 65 2e 64 6c 6c } //1 C:\Flopers\Flopers2\Bilore.dll
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}