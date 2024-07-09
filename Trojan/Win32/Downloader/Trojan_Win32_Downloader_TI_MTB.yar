
rule Trojan_Win32_Downloader_TI_MTB{
	meta:
		description = "Trojan:Win32/Downloader.TI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {2b d0 81 f2 ?? ?? ?? ?? 03 55 0c 2b 15 ?? ?? ?? ?? 89 15 } //1
		$a_03_1 = {89 65 e8 81 f1 ?? ?? ?? ?? 83 c1 33 33 cf 83 c1 08 33 cb 89 0d } //1
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}