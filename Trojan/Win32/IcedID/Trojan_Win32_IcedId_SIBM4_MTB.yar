
rule Trojan_Win32_IcedId_SIBM4_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBM4!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {50 6f 70 75 6c 61 74 65 } //1 Populate
		$a_03_1 = {83 c5 04 69 [0-10] 81 fd ?? ?? ?? ?? 73 ?? [0-10] 90 18 [0-80] 8b 15 ?? ?? ?? ?? [0-10] 8b 8c 2a ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? [0-10] 89 8c 2a 90 1b 08 83 c5 04 [0-10] 81 fd } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}