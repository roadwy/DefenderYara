
rule TrojanDownloader_Win32_Delf_VD{
	meta:
		description = "TrojanDownloader:Win32/Delf.VD,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b 42 1c 8d 0c b0 8b 04 39 03 c7 89 45 ?? e9 } //1
		$a_02_1 = {66 c7 40 24 60 00 89 ?? 28 64 a1 30 00 00 00 8b 40 10 } //3
		$a_00_2 = {38 70 69 6e 65 73 2e 63 6f 6d 2f 64 6f 77 6e 2e 74 78 74 } //3 8pines.com/down.txt
		$a_00_3 = {25 73 5c 73 25 64 2e 65 78 65 } //1 %s\s%d.exe
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*3+(#a_00_2  & 1)*3+(#a_00_3  & 1)*1) >=4
 
}