
rule Trojan_Win32_WrapAgent_AF_MTB{
	meta:
		description = "Trojan:Win32/WrapAgent.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f af c8 89 ?? dc 8d 85 ?? ?? ?? ?? 0f b7 c8 b8 ?? ?? ?? ?? f7 e9 c1 fa ?? 8b fa c1 ef ?? 8b ?? dc 03 c2 03 f8 8b 85 ?? ?? ?? ?? 0f b7 c0 2b f8 2b 3d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}