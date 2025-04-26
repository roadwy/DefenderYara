
rule TrojanDownloader_Win32_Drixed_E{
	meta:
		description = "TrojanDownloader:Win32/Drixed.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 4d 0c 30 08 8b c7 42 e8 ?? ?? ?? ?? 3b d0 7c e7 } //1
		$a_01_1 = {bf ef be ad de eb 1e 6a 04 8d 43 0c 68 } //1
		$a_01_2 = {80 30 aa 42 3b d6 7c ef } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}