
rule TrojanDownloader_Win32_Small_AK{
	meta:
		description = "TrojanDownloader:Win32/Small.AK,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //1 \drivers\etc\hosts
		$a_01_1 = {57 69 6e 45 78 65 63 } //1 WinExec
		$a_01_2 = {4e 65 74 62 69 6f 73 } //1 Netbios
		$a_00_3 = {53 56 8b 74 24 0c 57 8b fe 83 c9 ff 33 c0 33 db f2 ae f7 d1 49 74 2e 55 bd 60 22 40 00 6a 00 55 55 6a ff e8 } //1
		$a_00_4 = {6a 10 33 c0 59 8d 7d c0 f3 ab 6a 3f 8d bd a0 fe ff ff 59 c6 45 c0 37 f3 ab 66 ab aa 8d 85 a0 fe ff ff 66 c7 45 c8 ff 00 89 45 c4 8d 45 c0 50 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}