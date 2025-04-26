
rule TrojanDownloader_Win32_Drixed_F{
	meta:
		description = "TrojanDownloader:Win32/Drixed.F,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {ef be ad de eb 90 09 01 00 90 17 02 01 01 bf be } //1
		$a_01_1 = {80 30 aa 42 3b d6 7c ef } //1
		$a_01_2 = {c7 40 08 f7 28 9e 50 } //1
		$a_03_3 = {8d 78 10 8b 45 ?? 8b 55 ?? 33 07 33 57 04 83 65 0c 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}