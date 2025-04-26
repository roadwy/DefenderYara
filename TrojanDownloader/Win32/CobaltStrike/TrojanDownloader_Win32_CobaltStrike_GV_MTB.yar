
rule TrojanDownloader_Win32_CobaltStrike_GV_MTB{
	meta:
		description = "TrojanDownloader:Win32/CobaltStrike.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_1 = {3a 2f 2f 30 78 31 2e 73 6f 63 69 61 6c } //2 ://0x1.social
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}