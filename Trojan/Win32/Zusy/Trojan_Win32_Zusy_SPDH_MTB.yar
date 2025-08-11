
rule Trojan_Win32_Zusy_SPDH_MTB{
	meta:
		description = "Trojan:Win32/Zusy.SPDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {e8 29 16 00 00 83 ec 0c 89 c3 c7 44 24 04 ?? ?? ?? ?? 89 04 24 e8 d4 13 00 00 83 ec 08 89 c6 85 c0 0f 85 ?? ?? ?? ?? c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 ec 04 66 85 c0 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}