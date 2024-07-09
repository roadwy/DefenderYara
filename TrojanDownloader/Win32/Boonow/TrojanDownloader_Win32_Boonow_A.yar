
rule TrojanDownloader_Win32_Boonow_A{
	meta:
		description = "TrojanDownloader:Win32/Boonow.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {57 69 6e 64 6f 77 73 20 55 70 64 61 74 65 20 53 65 72 76 69 63 65 [0-10] 53 6f 66 74 77 61 72 65 5c 6e 65 77 62 61 79 } //1
		$a_01_1 = {50 61 79 6c 6f 61 64 20 64 6f 77 6e 6c 6f 61 64 65 64 } //1 Payload downloaded
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}