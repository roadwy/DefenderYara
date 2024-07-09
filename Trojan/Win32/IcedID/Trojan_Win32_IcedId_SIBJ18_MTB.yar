
rule Trojan_Win32_IcedId_SIBJ18_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ18!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {48 61 70 70 65 6e 2e 70 64 62 } //1 Happen.pdb
		$a_03_1 = {83 c7 04 81 ff ?? ?? ?? ?? [0-10] 90 18 [0-60] 8b 2d ?? ?? ?? ?? [0-20] 8b b4 2f ?? ?? ?? ?? [0-30] 81 c6 d0 10 08 01 89 b4 2f ?? ?? ?? ?? 83 c7 04 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}