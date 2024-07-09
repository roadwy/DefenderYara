
rule Trojan_Win32_IcedId_SIBJ16_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ16!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {42 65 64 54 72 79 2e 70 64 62 } //1 BedTry.pdb
		$a_03_1 = {83 c1 04 89 4c 24 ?? 81 f9 ?? ?? ?? ?? 90 18 [0-e0] 8b 15 ?? ?? ?? ?? 03 54 24 90 1b 00 8b 8a ?? ?? ?? ?? [0-20] 81 c1 ?? ?? ?? ?? [0-10] 89 8a } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}