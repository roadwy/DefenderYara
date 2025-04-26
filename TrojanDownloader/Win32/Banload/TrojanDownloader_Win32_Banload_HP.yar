
rule TrojanDownloader_Win32_Banload_HP{
	meta:
		description = "TrojanDownloader:Win32/Banload.HP,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {7c 2e 43 33 ff 8d 45 f8 50 8b 45 fc e8 ?? ?? ?? ff 8b d0 2b d7 b9 01 00 00 00 8b 45 fc e8 ?? ?? ?? ff 8b 55 f8 8b c6 e8 ?? ?? ?? ff 47 4b 75 d5 } //4
		$a_01_1 = {2f 2f 3a 70 74 74 68 } //1 //:ptth
		$a_01_2 = {73 72 65 76 69 72 64 } //1 srevird
		$a_01_3 = {6f 76 69 75 71 72 41 } //1 oviuqrA
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}