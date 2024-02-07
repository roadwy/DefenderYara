
rule Ransom_MSIL_Juwon_A_MTB{
	meta:
		description = "Ransom:MSIL/Juwon.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 77 72 61 6e 73 6f 6d 65 77 61 72 65 5f 4c 6f 61 64 } //01 00  jwransomeware_Load
		$a_01_1 = {6a 75 77 6f 6e 52 61 6e 73 6f 6d 65 77 61 72 65 2e 65 78 65 } //01 00  juwonRansomeware.exe
		$a_01_2 = {6a 75 77 6f 6e 52 61 6e 73 6f 6d 65 77 61 72 65 2e 70 64 62 } //01 00  juwonRansomeware.pdb
		$a_01_3 = {53 00 6f 00 72 00 72 00 79 00 2e 00 20 00 54 00 68 00 65 00 20 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 69 00 73 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 62 00 79 00 20 00 61 00 20 00 6d 00 69 00 6c 00 69 00 74 00 61 00 72 00 79 00 20 00 6c 00 65 00 76 00 65 00 6c 00 20 00 61 00 6c 00 67 00 6f 00 72 00 69 00 74 00 68 00 6d 00 20 00 62 00 79 00 } //01 00  Sorry. The computer is encrypted by a military level algorithm by
		$a_01_4 = {6a 00 77 00 20 00 72 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 20 00 61 00 6e 00 64 00 20 00 63 00 61 00 6e 00 20 00 6e 00 6f 00 74 00 20 00 62 00 65 00 20 00 61 00 63 00 63 00 65 00 73 00 73 00 65 00 64 00 2e 00 20 00 54 00 6f 00 20 00 72 00 65 00 63 00 6f 00 76 00 65 00 72 00 2c 00 20 00 79 00 6f 00 75 00 20 00 6d 00 75 00 73 00 74 00 20 00 65 00 6e 00 74 00 65 00 72 00 } //00 00  jw ransomware and can not be accessed. To recover, you must enter
		$a_00_5 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}