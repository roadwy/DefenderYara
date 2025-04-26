
rule Trojan_O97M_Obfuse_AV{
	meta:
		description = "Trojan:O97M/Obfuse.AV,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 73 45 72 72 6f 72 20 43 56 45 72 72 28 } //1 IsError CVErr(
		$a_00_1 = {22 4d 64 2e 90 02 06 22 20 2b 20 46 6f 72 6d 61 74 28 43 68 72 57 28 } //1
		$a_00_2 = {5e 62 5e 67 5e 42 5e 30 5e 41 5e 43 5e 6b 5e 41 5e 4c 5e 67 5e 42 5e 45 5e 41 5e 47 5e 38 5e 41 5e 64 5e 77 5e 42 5e 75 5e 41 5e 47 5e 77 5e } //1 ^b^g^B^0^A^C^k^A^L^g^B^E^A^G^8^A^d^w^B^u^A^G^w^
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}