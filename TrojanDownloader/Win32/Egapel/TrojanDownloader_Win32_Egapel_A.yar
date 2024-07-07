
rule TrojanDownloader_Win32_Egapel_A{
	meta:
		description = "TrojanDownloader:Win32/Egapel.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f 3f 07 0b c7 45 } //1
		$a_01_1 = {25 73 3f 6d 61 63 3d 25 73 26 76 65 72 3d 25 73 26 6f 73 3d 25 73 } //1 %s?mac=%s&ver=%s&os=%s
		$a_01_2 = {80 f9 56 75 08 8a 10 40 80 fa 56 74 f8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}