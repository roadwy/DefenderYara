
rule Trojan_Win32_SmokeLoader_XII_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.XII!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 03 c5 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 75 ?? 57 57 57 57 ff 15 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 8d 44 24 ?? e8 ?? ?? ?? ?? 83 6c 24 ?? ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}