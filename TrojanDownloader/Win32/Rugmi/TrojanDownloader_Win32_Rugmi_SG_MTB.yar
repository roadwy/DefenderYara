
rule TrojanDownloader_Win32_Rugmi_SG_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.SG!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 00 69 00 64 00 64 00 65 00 6e 00 } //1 Hidden
		$a_01_1 = {57 00 69 00 78 00 42 00 75 00 72 00 6e 00 } //1 WixBurn
		$a_01_2 = {61 00 70 00 68 00 61 00 67 00 69 00 61 00 2e 00 65 00 78 00 65 00 } //1 aphagia.exe
		$a_01_3 = {2f 00 2f 00 61 00 70 00 70 00 73 00 79 00 6e 00 64 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 6f 00 72 00 67 00 } //1 //appsyndication.org
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}