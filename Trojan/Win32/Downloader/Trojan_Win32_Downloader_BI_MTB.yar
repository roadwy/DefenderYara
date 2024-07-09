
rule Trojan_Win32_Downloader_BI_MTB{
	meta:
		description = "Trojan:Win32/Downloader.BI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {0f b6 08 0f b6 1d ?? ?? ?? ?? 2b cb 81 e1 ?? ?? ?? ?? 79 08 49 81 c9 ?? ?? ?? ?? 41 88 08 40 4a 75 de } //1
		$a_01_1 = {8b 1c 01 33 1c 11 75 0a 83 c1 04 78 f3 } //1
		$a_01_2 = {50 61 79 6c 6f 61 64 20 50 6f 73 69 74 69 6f 6e } //1 Payload Position
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_4 = {44 3a 5c 72 75 6e 6e 65 72 5c 73 6f 75 72 63 65 73 5c 72 75 6e 6e 65 72 2e 64 70 72 } //1 D:\runner\sources\runner.dpr
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}