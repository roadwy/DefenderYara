
rule TrojanDownloader_Win32_Rochap_T{
	meta:
		description = "TrojanDownloader:Win32/Rochap.T,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {8b 83 d4 03 00 00 ff 70 08 68 ?? ?? ?? 00 8b 83 cc 03 00 00 ff 70 08 68 ?? ?? ?? 00 8b 83 d0 03 00 00 ff 70 08 68 ?? ?? ?? 00 8d 45 c4 } //1
		$a_01_1 = {54 47 68 6f 73 74 31 } //1 TGhost1
		$a_01_2 = {54 6d 72 55 41 43 54 69 6d 65 72 } //1 TmrUACTimer
		$a_01_3 = {54 6d 72 44 6f 77 6e 54 69 6d 65 72 } //1 TmrDownTimer
		$a_01_4 = {6f 70 6a 74 73 66 58 75 6f 66 73 73 76 44 } //1 opjtsfXuofssvD
		$a_01_5 = {75 62 75 74 75 70 70 63 } //1 ubutuppc
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}