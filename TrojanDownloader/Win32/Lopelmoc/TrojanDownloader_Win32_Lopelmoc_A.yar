
rule TrojanDownloader_Win32_Lopelmoc_A{
	meta:
		description = "TrojanDownloader:Win32/Lopelmoc.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 f9 7e 7d 25 0f be 55 cf 83 fa 4f 7d 0c 0f be 45 cf 83 c0 2f } //1
		$a_03_1 = {83 c1 01 89 8d 90 01 02 ff ff 81 bd 90 01 02 ff ff 80 96 98 00 7d 4e 90 00 } //1
		$a_03_2 = {6b c0 3c 69 c0 e8 03 00 00 50 ff 15 90 01 04 8b 8d 90 01 02 ff ff d1 e1 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}