
rule TrojanDownloader_Win32_Small_CCC{
	meta:
		description = "TrojanDownloader:Win32/Small.CCC,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {b8 20 20 20 20 0b ?? 81 ?? 65 78 70 6c 0f 85 ?? 00 00 00 8b ?? 04 0b ?? 81 ?? 6f 72 65 72 0f 85 ?? 00 00 00 8b ?? 08 0b ?? 81 ?? 2e 65 78 65 0f 85 ?? 00 00 00 } //10
		$a_00_1 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 explorer.exe
		$a_00_2 = {70 73 61 70 69 2e 64 6c 6c } //1 psapi.dll
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=12
 
}