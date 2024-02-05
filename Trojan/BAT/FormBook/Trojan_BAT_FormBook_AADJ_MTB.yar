
rule Trojan_BAT_FormBook_AADJ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AADJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {51 75 61 6e 4c 79 42 61 6e 43 6f 66 66 65 65 31 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //02 00 
		$a_01_1 = {51 75 61 6e 4c 79 42 61 6e 43 6f 66 66 65 65 31 2e 46 6f 72 6d 4c 6f 61 64 69 6e 67 2e 72 65 73 6f 75 72 63 65 73 } //01 00 
		$a_01_2 = {47 65 74 50 69 78 65 6c } //00 00 
	condition:
		any of ($a_*)
 
}