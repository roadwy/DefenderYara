
rule Trojan_Win32_IcedId_SIBJ3_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ3!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {4f 69 6c 2e 64 6c 6c } //1 Oil.dll
		$a_03_1 = {83 c0 04 89 [0-0a] 89 44 24 ?? 3d ?? ?? ?? ?? 73 ?? [0-0a] 90 18 [0-3a] 03 2d ?? ?? ?? ?? [0-10] 8b 85 ?? ?? ?? ?? 89 44 24 ?? [0-55] 8b 44 24 90 1b 0a 05 ?? ?? ?? ?? [0-0a] 89 85 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}