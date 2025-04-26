
rule TrojanDownloader_Win32_Screem_AR_MSR{
	meta:
		description = "TrojanDownloader:Win32/Screem.AR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 49 00 4e 00 54 00 45 00 52 00 4e 00 41 00 4c 00 5c 00 52 00 45 00 4d 00 4f 00 54 00 45 00 2e 00 45 00 58 00 45 00 } //2 C:\INTERNAL\REMOTE.EXE
		$a_00_1 = {6a 71 69 75 61 72 72 69 76 69 6b 67 6a 76 64 71 69 75 66 } //1 jqiuarrivikgjvdqiuf
		$a_00_2 = {76 64 70 6f 61 71 72 76 79 74 61 79 6f 61 79 67 6b } //1 vdpoaqrvytayoaygk
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}