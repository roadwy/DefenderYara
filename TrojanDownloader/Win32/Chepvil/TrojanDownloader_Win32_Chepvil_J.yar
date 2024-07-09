
rule TrojanDownloader_Win32_Chepvil_J{
	meta:
		description = "TrojanDownloader:Win32/Chepvil.J,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {0f be 04 03 0f b6 97 ?? ?? ?? ?? 31 d0 88 86 } //1
		$a_03_1 = {0f be 04 10 8b 55 ?? 0f b6 92 ?? ?? ?? ?? 31 d0 88 87 } //1
		$a_03_2 = {0f be 04 08 8b 4d ?? 0f b6 89 ?? ?? ?? ?? 31 c8 88 82 } //1
		$a_03_3 = {32 44 11 01 88 86 90 09 06 00 8a 04 10 8b 4d } //1
		$a_03_4 = {80 3c 18 2f 75 [0-08] 8d (44|54) 18 01 } //4
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*4) >=5
 
}