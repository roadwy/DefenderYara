
rule Ransom_MSIL_LockScreen_F{
	meta:
		description = "Ransom:MSIL/LockScreen.F,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 00 79 00 6c 00 20 00 7a 00 61 00 62 00 6c 00 6f 00 6b 00 6f 00 76 00 e1 00 6e 00 21 00 } //01 00 
		$a_01_1 = {70 00 6c 00 61 00 74 00 69 00 74 00 20 00 6b 00 72 00 65 00 64 00 69 00 74 00 6e 00 } //01 00 
		$a_03_2 = {5c 00 52 00 75 00 6e 00 90 01 02 50 00 4f 00 4c 00 49 00 43 00 49 00 45 00 90 00 } //01 00 
		$a_01_3 = {62 6c 6f 63 6b 5f 46 6f 72 6d 43 6c 6f 73 69 6e 67 00 } //00 00 
		$a_00_4 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}