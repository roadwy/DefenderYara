
rule Trojan_Win32_IcedId_SIBJ16_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ16!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {42 65 64 54 72 79 2e 70 64 62 } //1 BedTry.pdb
		$a_03_1 = {83 c1 04 89 4c 24 90 01 01 81 f9 90 01 04 90 18 90 02 e0 8b 15 90 01 04 03 54 24 90 1b 00 8b 8a 90 01 04 90 02 20 81 c1 90 01 04 90 02 10 89 8a 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}