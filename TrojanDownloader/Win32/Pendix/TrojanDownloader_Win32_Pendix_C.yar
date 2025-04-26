
rule TrojanDownloader_Win32_Pendix_C{
	meta:
		description = "TrojanDownloader:Win32/Pendix.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8d 7d c0 b9 10 00 00 00 b8 dd dd cc cc f3 ab 6a 00 6a 00 68 5c 10 40 00 68 1c 10 40 00 ?? ?? e8 41 00 00 00 } //2
		$a_02_1 = {68 5c 10 40 00 [0-05] 68 1c 10 40 00 [0-05] e8 41 00 00 00 } //1
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*1) >=1
 
}