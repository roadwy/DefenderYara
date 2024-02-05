
rule Trojan_Win32_Emotet_DDV_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {61 6d 75 4e 78 45 63 6f 6c 6c 41 6c 61 75 74 72 69 56 } //01 00 
		$a_81_1 = {33 4e 4a 37 32 68 6c 68 57 76 66 37 37 36 39 52 6d 64 6e 74 39 5a 36 44 56 4f } //01 00 
		$a_81_2 = {4f 6d 69 48 4c 48 74 4e 41 39 68 57 46 72 6f } //01 00 
		$a_81_3 = {46 44 43 63 7a 63 78 78 78 47 47 48 38 37 33 34 39 35 37 34 38 74 67 68 6a 68 66 6a } //01 00 
		$a_81_4 = {51 51 79 76 67 53 35 50 50 34 75 61 45 6e 4c } //00 00 
	condition:
		any of ($a_*)
 
}