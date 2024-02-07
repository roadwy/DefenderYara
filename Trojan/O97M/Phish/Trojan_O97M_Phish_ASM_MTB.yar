
rule Trojan_O97M_Phish_ASM_MTB{
	meta:
		description = "Trojan:O97M/Phish.ASM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 28 69 77 72 20 68 74 74 70 73 3a 2f 2f 7a 65 76 6f 64 61 79 2e 62 6c 6f 67 73 70 6f 74 2e 63 6f 6d 2f 61 74 6f 6d 2e 78 6d 6c 20 2d } //01 00  $(iwr https://zevoday.blogspot.com/atom.xml -
		$a_01_1 = {61 6c 73 29 20 7c 20 26 28 27 41 4a 53 41 4d 53 4a 57 57 55 41 55 27 2e 72 65 70 6c 61 63 65 28 27 41 4a 53 41 4d 53 4a 57 57 55 41 55 27 2c 27 49 27 } //00 00  als) | &('AJSAMSJWWUAU'.replace('AJSAMSJWWUAU','I'
	condition:
		any of ($a_*)
 
}