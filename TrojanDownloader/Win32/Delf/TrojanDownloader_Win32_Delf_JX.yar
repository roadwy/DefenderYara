
rule TrojanDownloader_Win32_Delf_JX{
	meta:
		description = "TrojanDownloader:Win32/Delf.JX,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 54 54 50 2f 31 2e 30 20 32 30 30 20 4f 4b } //1 HTTP/1.0 200 OK
		$a_01_1 = {49 66 20 65 78 69 73 74 20 22 25 73 22 20 47 6f 74 6f 20 31 } //1 If exist "%s" Goto 1
		$a_01_2 = {47 74 66 78 69 6e 73 74 61 6c 6c } //2 Gtfxinstall
		$a_02_3 = {68 d0 07 00 00 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 cf 09 00 00 e8 ?? ?? ?? ?? 6a 00 ff 36 68 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_02_3  & 1)*2) >=4
 
}