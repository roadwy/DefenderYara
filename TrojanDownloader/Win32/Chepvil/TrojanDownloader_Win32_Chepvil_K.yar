
rule TrojanDownloader_Win32_Chepvil_K{
	meta:
		description = "TrojanDownloader:Win32/Chepvil.K,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_00_0 = {2f 66 2f 67 2e 70 68 70 } //10 /f/g.php
		$a_00_1 = {0f be 45 00 0f be 75 01 33 f0 b8 00 00 00 00 76 14 } //1
		$a_02_2 = {0f be 40 01 8b 95 90 01 01 fc ff ff 0f be 12 31 d0 89 85 90 01 01 fc ff ff 90 00 } //1
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=11
 
}