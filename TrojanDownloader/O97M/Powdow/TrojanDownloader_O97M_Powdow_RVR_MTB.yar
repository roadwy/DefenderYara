
rule TrojanDownloader_O97M_Powdow_RVR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 6e 65 77 3a 31 33 37 30 39 36 32 30 2d 43 32 37 39 2d 31 31 43 45 2d 41 34 39 45 2d 34 34 34 35 35 33 35 34 30 30 30 30 22 29 } //1 CreateObject("new:13709620-C279-11CE-A49E-444553540000")
		$a_01_1 = {6f 62 6a 4d 4d 43 31 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 64 64 2c 20 22 68 74 74 70 3a 2f 2f 62 69 74 6c 79 2e 63 6f 6d 2f 61 73 64 61 73 64 6a 71 77 68 64 69 6f 71 75 77 68 6b 22 2c 20 22 22 2c } //1 objMMC1.ShellExecute dd, "http://bitly.com/asdasdjqwhdioquwhk", "",
		$a_01_2 = {73 68 2e 54 65 78 74 46 72 61 6d 65 2e 54 65 78 74 52 61 6e 67 65 2e 54 65 78 74 } //1 sh.TextFrame.TextRange.Text
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}