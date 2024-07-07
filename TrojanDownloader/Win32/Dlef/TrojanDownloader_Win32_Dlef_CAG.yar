
rule TrojanDownloader_Win32_Dlef_CAG{
	meta:
		description = "TrojanDownloader:Win32/Dlef.CAG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {64 a1 30 00 00 00 8b 40 0c 90 01 02 0c 8b 00 90 00 } //1
		$a_00_1 = {6b 6b 69 6c 6c 20 2f 69 6d 20 65 78 70 6c 6f 72 65 72 } //1 kkill /im explorer
		$a_00_2 = {39 31 2e 32 30 37 2e 36 2e 31 32 32 } //2 91.207.6.122
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2) >=3
 
}