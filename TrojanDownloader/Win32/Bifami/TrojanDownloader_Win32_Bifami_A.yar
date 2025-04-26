
rule TrojanDownloader_Win32_Bifami_A{
	meta:
		description = "TrojanDownloader:Win32/Bifami.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 00 65 00 6e 00 74 00 20 00 4b 00 65 00 79 00 20 00 35 00 4b 00 2d 00 48 00 4a 00 38 00 39 00 45 00 52 00 64 00 } //1 Sent Key 5K-HJ89ERd
		$a_01_1 = {53 00 65 00 6e 00 74 00 20 00 4b 00 65 00 79 00 20 00 47 00 36 00 6b 00 2d 00 33 00 33 00 52 00 42 00 6e 00 32 00 } //1 Sent Key G6k-33RBn2
		$a_01_2 = {5c 00 61 00 74 00 69 00 65 00 63 00 6c 00 78 00 2e 00 76 00 62 00 73 00 } //1 \atieclx.vbs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}