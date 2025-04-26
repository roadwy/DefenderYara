
rule Trojan_Win32_Zusy_INI_MTB{
	meta:
		description = "Trojan:Win32/Zusy.INI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 8b cd 8d 44 24 ?? 89 54 24 ?? e8 33 fe ff ff 8b 44 24 20 31 44 24 10 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 57 57 57 ff 15 ?? ?? ?? ?? 8b 44 24 10 33 44 24 24 89 44 24 10 2b f0 8d 44 24 28 e8 ?? ?? ?? ?? 83 6c 24 ?? ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}