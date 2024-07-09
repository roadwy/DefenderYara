
rule TrojanDownloader_Win32_Zlob_ZF{
	meta:
		description = "TrojanDownloader:Win32/Zlob.ZF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {bb 40 4b 4c 00 [0-10] 4f c1 ef (02|03) 47 4b 75 f1 } //1
		$a_01_1 = {57 65 62 20 54 65 63 68 6e 6f 6c 6f 67 69 65 73 00 } //1
		$a_01_2 = {61 77 65 72 25 64 2e 62 61 74 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}