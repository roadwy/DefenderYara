
rule Ransom_MSIL_Genasom_MTB{
	meta:
		description = "Ransom:MSIL/Genasom!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {52 61 6e 73 6f 6d 2e 42 4c } //01 00  Ransom.BL
		$a_00_1 = {52 61 6e 73 6f 6d 2e 50 4c } //02 00  Ransom.PL
		$a_01_2 = {79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //02 00  your files have been encrypted
		$a_00_3 = {52 61 6e 73 6f 6d 77 61 72 65 2e 72 65 73 6f 75 72 63 65 73 } //00 00  Ransomware.resources
		$a_00_4 = {5d 04 00 } //00 86 
	condition:
		any of ($a_*)
 
}