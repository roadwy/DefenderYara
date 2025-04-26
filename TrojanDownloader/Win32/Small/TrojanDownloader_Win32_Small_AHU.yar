
rule TrojanDownloader_Win32_Small_AHU{
	meta:
		description = "TrojanDownloader:Win32/Small.AHU,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 46 6c 61 73 68 47 61 6d 65 53 65 74 75 70 2e 65 78 65 } //1 C:\FlashGameSetup.exe
		$a_01_1 = {31 31 39 2e 31 34 37 2e 32 34 32 2e 37 35 2f 46 6c 61 73 68 47 61 6d 65 53 65 74 75 70 2e 65 78 65 } //1 119.147.242.75/FlashGameSetup.exe
		$a_01_2 = {43 00 3a 00 5c 00 46 00 6c 00 61 00 73 00 68 00 47 00 61 00 6d 00 65 00 53 00 65 00 74 00 75 00 70 00 2e 00 65 00 78 00 65 00 } //1 C:\FlashGameSetup.exe
		$a_01_3 = {31 00 31 00 39 00 2e 00 31 00 34 00 37 00 2e 00 32 00 34 00 32 00 2e 00 37 00 35 00 2f 00 46 00 6c 00 61 00 73 00 68 00 47 00 61 00 6d 00 65 00 53 00 65 00 74 00 75 00 70 00 2e 00 65 00 78 00 65 00 } //1 119.147.242.75/FlashGameSetup.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}