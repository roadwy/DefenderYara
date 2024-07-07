
rule Trojan_Win32_IcedId_SIBJ2_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ2!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {4d 69 6c 6c 69 6f 6e 53 75 6d 6d 65 72 5c 53 70 72 69 6e 67 2e 70 64 62 } //1 MillionSummer\Spring.pdb
		$a_03_1 = {83 c2 04 89 90 02 0a 81 fa 90 01 04 90 18 90 02 2a 8b 1d 90 01 04 8b b4 13 90 01 04 90 02 40 81 c6 f4 49 0a 01 89 b4 13 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}