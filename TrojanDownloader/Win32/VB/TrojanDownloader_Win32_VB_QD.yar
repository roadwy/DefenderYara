
rule TrojanDownloader_Win32_VB_QD{
	meta:
		description = "TrojanDownloader:Win32/VB.QD,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 6a 65 63 74 31 2e 55 73 65 72 43 6f 6e 74 72 6f 6c 31 } //1 Project1.UserControl1
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 65 00 61 00 74 00 65 00 67 00 67 00 73 00 6d 00 6f 00 72 00 65 00 2e 00 69 00 6e 00 66 00 6f 00 2f 00 } //1 http://eateggsmore.info/
		$a_01_2 = {47 00 41 00 59 00 47 00 41 00 59 00 2e 00 65 00 78 00 65 00 } //1 GAYGAY.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}