
rule Trojan_Win32_IcedId_SIBJ6_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ6!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {43 6f 75 6e 74 46 72 65 65 5c 54 65 61 63 68 2e 70 64 62 } //1 CountFree\Teach.pdb
		$a_03_1 = {83 c5 04 83 [0-05] 81 fd ?? ?? ?? ?? [0-0a] 90 18 [0-50] a1 ?? ?? ?? ?? [0-0a] 8b 94 28 ?? ?? ?? ?? [0-4a] 81 c2 ?? ?? ?? ?? [0-0a] a1 90 1b 05 89 94 28 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}