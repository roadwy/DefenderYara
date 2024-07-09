
rule Trojan_Win32_Smokeloader_CCEV_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.CCEV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d3 d3 ea 8d 04 1f 89 45 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 03 55 ?? 8b 45 ?? 31 45 ?? 33 55 ?? 89 55 ?? 8b 45 ?? 83 45 ?? ?? 29 45 ?? 83 6d ?? ?? 83 3d } //1
		$a_03_1 = {8b c2 d3 e8 03 fa 03 45 ?? 33 c7 31 45 ?? 2b 5d ?? 8d 45 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}