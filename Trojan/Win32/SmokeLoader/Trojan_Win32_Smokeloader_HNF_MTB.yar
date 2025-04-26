
rule Trojan_Win32_Smokeloader_HNF_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.HNF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 75 f0 81 45 f0 00 00 00 00 8b 45 f0 } //1
		$a_03_1 = {d3 ea 03 d3 8b ?? ?? 31 45 ?? 31 55 ?? 2b 7d fc 81 45 ?? ?? ?? ?? ?? ff 4d ?? 0f 85 } //1
		$a_03_2 = {3d a9 0f 00 00 [0-60] 83 45 ?? 64 29 45 90 1b 01 83 6d 90 1b 01 64 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}