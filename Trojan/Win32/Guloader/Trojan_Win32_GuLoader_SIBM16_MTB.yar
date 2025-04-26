
rule Trojan_Win32_GuLoader_SIBM16_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SIBM16!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {62 00 6f 00 6e 00 64 00 73 00 68 00 69 00 70 00 } //1 bondship
		$a_03_1 = {83 c2 04 80 [0-30] 81 fa ?? ?? ?? ?? 90 18 [0-30] 81 34 17 ?? ?? ?? ?? [0-30] 83 c2 04 [0-30] 81 fa ?? ?? ?? ?? 0f 85 ?? ?? ?? ?? [0-30] ff e7 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}