
rule Trojan_Win32_GuLoader_SIBM15_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SIBM15!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d2 89 d2 [0-0a] 81 ea ?? ?? ?? ?? [0-10] 81 f2 ?? ?? ?? ?? [0-40] 81 ea ?? ?? ?? ?? [0-20] 33 14 31 [0-10] 81 f2 ?? ?? ?? ?? [0-40] 8b 1c 24 [0-0a] 01 14 33 [0-10] 83 ee 04 0f 8d ?? ?? ?? ?? [0-0a] c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}