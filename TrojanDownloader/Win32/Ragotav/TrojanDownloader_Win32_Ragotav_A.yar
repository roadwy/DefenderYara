
rule TrojanDownloader_Win32_Ragotav_A{
	meta:
		description = "TrojanDownloader:Win32/Ragotav.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 6c 00 6f 00 61 00 64 00 65 00 72 00 32 00 30 00 31 00 35 00 5c 00 6c 00 6f 00 61 00 64 00 65 00 72 00 32 00 30 00 31 00 35 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //1 \Desktop\loader2015\loader2015\Project1.vbp
		$a_01_1 = {72 6f 64 61 6e 64 6f 00 63 6f 6e 66 69 67 75 72 61 72 00 00 6f 63 6f 6e 74 61 32 00 6f 63 6f 6e 74 61 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}