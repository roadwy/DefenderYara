
rule Trojan_Win32_IcedId_SIBJ7_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ7!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {64 72 61 77 2e 70 64 62 } //1 draw.pdb
		$a_03_1 = {83 c2 04 89 55 ?? 81 7d 90 1b 00 ?? ?? ?? ?? 0f 83 ?? ?? ?? ?? [0-93] [0-93] 8b 0d ?? ?? ?? ?? 03 4d 90 1b 00 8b 91 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? [0-70] 8b 0d 90 1b 09 81 c1 ?? ?? ?? ?? 89 0d 90 1b 09 8b 15 90 1b 06 03 55 90 1b 00 a1 90 1b 09 89 82 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}