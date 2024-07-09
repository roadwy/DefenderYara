
rule TrojanDownloader_Win32_Zlob_gen_BJ{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!BJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {25 73 5c 7a 66 25 73 25 64 2e 65 78 65 } //2 %s\zf%s%d.exe
		$a_03_1 = {8d 4c 24 14 51 68 ?? ?? 40 00 57 ff d3 83 c4 14 57 46 ff d5 83 f8 ff 75 e1 } //1
		$a_03_2 = {8d 85 fc fe ff ff 50 68 ?? ?? 40 00 ff 75 08 ff 15 ?? ?? 40 00 83 c4 14 ff 75 08 46 ff 15 ?? ?? 40 00 83 f8 ff 75 d3 } //1
	condition:
		((#a_00_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}