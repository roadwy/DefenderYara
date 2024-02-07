
rule Trojan_Win32_Downloader_BY_MTB{
	meta:
		description = "Trojan:Win32/Downloader.BY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {a1 28 f6 63 00 8a 84 06 90 02 04 8b 0d 90 02 04 88 04 0e 90 00 } //01 00 
		$a_03_1 = {03 c8 33 d1 8b 4d 90 01 01 d3 e8 c7 05 90 02 08 03 45 90 01 01 33 c2 89 45 90 00 } //01 00 
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00  VirtualAlloc
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00  IsDebuggerPresent
	condition:
		any of ($a_*)
 
}