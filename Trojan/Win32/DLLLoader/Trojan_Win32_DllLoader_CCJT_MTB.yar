
rule Trojan_Win32_DllLoader_CCJT_MTB{
	meta:
		description = "Trojan:Win32/DllLoader.CCJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {6b 65 72 6e c7 05 ?? ?? ?? ?? 65 6c 33 32 c7 05 ?? ?? ?? ?? 2e 64 6c 6c c7 05 ?? ?? ?? ?? 77 69 6e 63 c7 05 ?? ?? ?? ?? 72 2e 64 6c } //2
		$a_03_1 = {ff d6 83 ec 14 85 c0 75 ?? c7 04 24 ?? ?? ?? ?? ff d3 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}