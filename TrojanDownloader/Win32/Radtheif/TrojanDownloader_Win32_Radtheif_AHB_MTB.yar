
rule TrojanDownloader_Win32_Radtheif_AHB_MTB{
	meta:
		description = "TrojanDownloader:Win32/Radtheif.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6e 6d 2e 65 78 65 } //30 C:\Windows\Systenm.exe
		$a_01_1 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 31 2e 62 69 6e } //10 C:\Windows\1.bin
		$a_01_2 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 61 77 65 73 6f 6d 69 75 6d 2e 64 6c 6c } //20 C:\Windows\awesomium.dll
		$a_03_3 = {8d 4d cc c7 45 fc 00 00 00 00 e8 ?? ?? ?? ?? 6a 05 6a 00 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 8b 55 cc 85 d2 74 } //40
	condition:
		((#a_01_0  & 1)*30+(#a_01_1  & 1)*10+(#a_01_2  & 1)*20+(#a_03_3  & 1)*40) >=100
 
}