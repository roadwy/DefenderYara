
rule TrojanDownloader_Win32_Potentialdownloader_A{
	meta:
		description = "TrojanDownloader:Win32/Potentialdownloader.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {50 e8 04 00 00 00 ?? ?? ?? ?? 58 2b 00 ff 10 } //1
		$a_02_1 = {ff 75 fc e8 ?? 00 00 00 68 74 74 70 3a 2f 2f } //1
		$a_00_2 = {64 a1 30 00 00 00 8b 40 0c 8b 70 1c } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}