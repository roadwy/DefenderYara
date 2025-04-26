
rule TrojanDownloader_Win32_Otlard_B{
	meta:
		description = "TrojanDownloader:Win32/Otlard.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {be 85 00 00 00 f7 fe 6b d2 03 03 ca 81 e1 ff 00 00 00 } //1
		$a_01_1 = {47 00 6f 00 6f 00 74 00 6b 00 69 00 74 00 53 00 53 00 4f 00 } //1 GootkitSSO
		$a_01_2 = {eb 01 46 80 3e 7c 75 fa } //1
		$a_01_3 = {6d 73 78 73 6c 74 2e 64 61 74 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}