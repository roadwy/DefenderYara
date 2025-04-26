
rule TrojanDownloader_O97M_Qakbot_KIL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.KIL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 6b 68 61 75 67 61 6c 6c 69 69 6e 64 69 61 2e 63 6f 6d 2f 64 73 2f 30 38 31 32 2e 67 69 66 } //1 https://khaugalliindia.com/ds/0812.gif
		$a_01_1 = {52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 RLDownloadToFileA
		$a_01_2 = {72 75 6e 64 6c 6c 33 32 } //1 rundll32
		$a_01_3 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}