
rule Trojan_Win32_IcedId_SIBJ19_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ19!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {73 77 69 6d 2e 70 64 62 } //1 swim.pdb
		$a_03_1 = {04 ff 4c 24 ?? [0-10] 8b 15 ?? ?? ?? ?? 89 11 90 18 [0-60] 8b 44 24 ?? [0-10] 8b 00 [0-10] a3 90 1b 02 [0-e0] 81 05 90 1b 02 ?? ?? ?? ?? [0-10] 8b 4c 24 ?? 83 44 24 ?? 04 ff 4c 24 ?? [0-10] 8b 15 90 1b 02 89 11 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}