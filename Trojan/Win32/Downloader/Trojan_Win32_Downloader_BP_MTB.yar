
rule Trojan_Win32_Downloader_BP_MTB{
	meta:
		description = "Trojan:Win32/Downloader.BP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 04 11 84 c0 74 09 3c 56 74 05 34 56 88 04 11 41 3b ce 7c eb } //01 00 
		$a_01_1 = {8a 54 07 01 88 14 06 40 3b c1 7c f4 } //01 00 
		$a_03_2 = {80 f1 56 88 88 90 02 04 83 c0 06 3d 90 02 04 0f 8c 90 00 } //01 00 
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_01_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00  VirtualAlloc
	condition:
		any of ($a_*)
 
}