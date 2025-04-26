
rule Trojan_Win32_PbrabLoader_A_MTB{
	meta:
		description = "Trojan:Win32/PbrabLoader.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 04 50 6b c0 ?? 0f b7 d7 66 2b c2 ba ?? ?? ?? ?? 66 2b 45 ?? 66 03 46 ?? 8b 75 ?? 66 2b c2 8b 55 ?? 83 c6 ?? 89 75 ?? 66 89 04 51 42 8b 7d } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}