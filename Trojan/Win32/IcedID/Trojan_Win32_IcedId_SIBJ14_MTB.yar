
rule Trojan_Win32_IcedId_SIBJ14_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ14!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {63 61 72 65 4d 61 6e 2e 70 64 62 } //1 careMan.pdb
		$a_03_1 = {83 c2 04 89 55 ?? 81 7d 90 1b 00 ?? ?? ?? ?? 0f 83 ?? ?? ?? ?? 90 08 8a 01 8b 15 ?? ?? ?? ?? 03 55 90 1b 00 8b 82 ?? ?? ?? ?? a3 ?? ?? ?? ?? 90 08 8a 01 8b 15 90 1b 08 81 c2 ?? ?? ?? ?? 89 15 90 1b 08 a1 90 1b 05 03 45 90 1b 00 8b 0d 90 1b 08 89 88 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}