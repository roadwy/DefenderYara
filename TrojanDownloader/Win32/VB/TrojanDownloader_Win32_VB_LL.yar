
rule TrojanDownloader_Win32_VB_LL{
	meta:
		description = "TrojanDownloader:Win32/VB.LL,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 6f 64 4f 70 65 6e 55 52 4c } //1 modOpenURL
		$a_01_1 = {47 75 73 61 6e 69 74 6f } //1 Gusanito
		$a_01_2 = {63 68 6b 41 75 74 6f 6d 61 74 69 63 6f } //1 chkAutomatico
		$a_01_3 = {70 68 61 72 } //1 phar
		$a_01_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}