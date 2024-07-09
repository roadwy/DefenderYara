
rule Trojan_Win32_Zenpak_GNA_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 18 31 d0 31 c2 83 f2 ?? 31 c2 31 2d ?? ?? ?? ?? 31 d0 89 35 ?? ?? ?? ?? 31 c2 42 83 c0 ?? 89 3d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Zenpak_GNA_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.GNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b b5 ec fe ff ff 8b 8d c0 fe ff ff 8a 1c 0e 32 9c 3d f4 fe ff ff 8b bd e8 fe ff ff 88 1c 0f 81 c1 01 00 00 00 8b b5 f0 fe ff ff 39 f1 8b b5 bc } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}