
rule TrojanDownloader_Win32_Astaroth_YY{
	meta:
		description = "TrojanDownloader:Win32/Astaroth.YY,SIGNATURE_TYPE_CMDHSTR_EXT,70 00 70 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 } //1 cmd.exe
		$a_00_1 = {5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 } //1 \ProgramData\
		$a_00_2 = {63 00 75 00 72 00 6c 00 20 00 2d 00 41 00 } //10 curl -A
		$a_02_3 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-ff] 2f 00 3f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 20 00 2d 00 6f 00 20 00 } //100
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*10+(#a_02_3  & 1)*100) >=112
 
}