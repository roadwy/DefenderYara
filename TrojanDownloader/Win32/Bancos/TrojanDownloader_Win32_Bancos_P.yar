
rule TrojanDownloader_Win32_Bancos_P{
	meta:
		description = "TrojanDownloader:Win32/Bancos.P,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8d 95 f0 fa ff ff b9 00 04 00 00 8b 45 f0 8b 30 ff 56 0c 8b f0 85 f6 74 10 8d 95 f0 fa ff ff } //1
		$a_01_1 = {21 6f 64 69 70 6d 6f 72 72 6f 43 20 6f 76 69 75 71 72 41 } //1 !odipmorroC oviuqrA
		$a_01_2 = {2f 2f 3a 70 74 74 68 } //1 //:ptth
		$a_01_3 = {73 72 65 76 69 72 64 } //1 srevird
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}