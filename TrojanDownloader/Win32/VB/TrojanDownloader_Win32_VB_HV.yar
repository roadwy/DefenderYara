
rule TrojanDownloader_Win32_VB_HV{
	meta:
		description = "TrojanDownloader:Win32/VB.HV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 66 00 66 00 2d 00 70 00 75 00 72 00 6b 00 2e 00 61 00 74 00 2f 00 ?? ?? 2e 00 6a 00 70 00 67 00 } //1
		$a_00_1 = {68 00 6f 00 74 00 6d 00 61 00 69 00 6c 00 6c 00 69 00 76 00 65 00 2e 00 64 00 6c 00 6c 00 } //1 hotmaillive.dll
		$a_00_2 = {68 00 6f 00 74 00 6d 00 61 00 69 00 6c 00 2e 00 64 00 6c 00 6c 00 } //1 hotmail.dll
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}