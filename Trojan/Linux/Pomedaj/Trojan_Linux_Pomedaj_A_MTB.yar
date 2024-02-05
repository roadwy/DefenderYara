
rule Trojan_Linux_Pomedaj_A_MTB{
	meta:
		description = "Trojan:Linux/Pomedaj.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {77 67 65 74 20 2d 63 20 70 6d 2e 69 70 66 73 77 61 6c 6c 65 74 2e 74 6b 2f } //01 00 
		$a_00_1 = {2f 75 73 72 2f 69 6e 63 6c 75 64 65 2f 70 6d 2e 74 61 72 2e 67 7a } //02 00 
		$a_00_2 = {b9 10 00 00 00 31 c0 48 89 e7 f3 48 ab 48 89 ea be b0 4f 49 00 48 89 e7 48 89 e3 e8 68 24 00 00 0f 1f 84 00 00 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}