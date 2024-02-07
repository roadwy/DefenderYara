
rule Trojan_Linux_Mirai_G_MTB{
	meta:
		description = "Trojan:Linux/Mirai.G!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_02_0 = {77 67 65 74 25 32 30 68 74 74 70 25 33 41 25 32 46 25 32 46 90 02 10 25 32 46 73 68 69 69 6e 61 2e 61 72 6d 25 33 42 63 68 6d 6f 64 25 32 30 37 37 37 25 32 30 73 68 69 69 6e 61 2e 61 72 6d 90 00 } //01 00 
		$a_02_1 = {77 67 65 74 20 68 74 74 70 3a 2f 2f 90 02 10 2f 73 68 69 69 6e 61 2e 73 68 90 00 } //01 00 
		$a_00_2 = {47 45 54 20 2f 73 68 65 6c 6c 3f 63 64 25 32 30 25 32 46 74 6d 70 } //00 00  GET /shell?cd%20%2Ftmp
		$a_00_3 = {e7 2f } //00 00 
	condition:
		any of ($a_*)
 
}