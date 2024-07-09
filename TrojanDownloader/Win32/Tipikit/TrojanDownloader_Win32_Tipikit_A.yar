
rule TrojanDownloader_Win32_Tipikit_A{
	meta:
		description = "TrojanDownloader:Win32/Tipikit.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {74 70 6b 74 73 6b 65 6e 64 2e 70 68 70 } //1 tpktskend.php
		$a_02_1 = {63 3a 5c 63 6f 6e 66 [0-01] 2e 6d 79 00 } //1
		$a_00_2 = {5f 73 76 63 68 6f 73 74 2e 65 78 65 00 } //1
		$a_00_3 = {49 6e 73 74 46 75 6e 00 } //1 湉瑳畆n
		$a_00_4 = {55 72 6c 6d 6f 6e 2e 64 6c 6c } //1 Urlmon.dll
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}