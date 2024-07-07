
rule TrojanDownloader_Win32_Chepvil_J{
	meta:
		description = "TrojanDownloader:Win32/Chepvil.J,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {0f be 04 03 0f b6 97 90 01 04 31 d0 88 86 90 00 } //1
		$a_03_1 = {0f be 04 10 8b 55 90 01 01 0f b6 92 90 01 04 31 d0 88 87 90 00 } //1
		$a_03_2 = {0f be 04 08 8b 4d 90 01 01 0f b6 89 90 01 04 31 c8 88 82 90 00 } //1
		$a_03_3 = {32 44 11 01 88 86 90 09 06 00 8a 04 10 8b 4d 90 00 } //1
		$a_03_4 = {80 3c 18 2f 75 90 02 08 8d 90 03 01 01 44 54 18 01 90 00 } //4
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*4) >=5
 
}