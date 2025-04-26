
rule Trojan_BAT_NjRat_AYA_MTB{
	meta:
		description = "Trojan:BAT/NjRat.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {24 65 31 61 65 32 38 30 61 2d 66 30 62 32 2d 34 33 61 65 2d 39 63 63 34 2d 33 65 34 61 34 65 39 63 37 36 61 37 } //2 $e1ae280a-f0b2-43ae-9cc4-3e4a4e9c76a7
		$a_01_1 = {63 61 73 61 20 35 34 } //1 casa 54
		$a_01_2 = {6f 62 6a 5c 52 65 6c 65 61 73 65 5c 53 6f 66 74 77 61 72 65 2e 70 64 62 } //1 obj\Release\Software.pdb
		$a_01_3 = {53 6f 66 74 77 61 72 65 2e 52 65 73 6f 75 72 63 65 73 } //1 Software.Resources
		$a_00_4 = {50 00 72 00 6f 00 70 00 65 00 72 00 74 00 79 00 20 00 63 00 61 00 6e 00 20 00 6f 00 6e 00 6c 00 79 00 20 00 62 00 65 00 20 00 73 00 65 00 74 00 20 00 74 00 6f 00 20 00 4e 00 6f 00 74 00 68 00 69 00 6e 00 67 00 } //1 Property can only be set to Nothing
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=6
 
}