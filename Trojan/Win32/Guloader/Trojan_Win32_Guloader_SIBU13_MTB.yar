
rule Trojan_Win32_Guloader_SIBU13_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SIBU13!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 81 34 07 ?? ?? ?? ?? [0-a0] 83 c0 04 [0-6a] 83 c1 00 [0-30] 3d ?? ?? ?? ?? [0-30] 0f 85 ?? ?? ?? ?? [0-ba] ff d7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}