
rule Ransom_Win32_Velso_AA_MTB{
	meta:
		description = "Ransom:Win32/Velso.AA!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 67 65 74 5f 6d 79 5f 66 69 6c 65 73 2e 74 78 74 } //01 00  \get_my_files.txt
		$a_01_1 = {48 65 6c 6c 6f 2e 20 49 66 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 74 75 72 6e 20 66 69 6c 65 73 2c 20 77 72 69 74 65 20 6d 65 20 74 6f 20 65 2d 6d 61 69 6c } //01 00  Hello. If you want to return files, write me to e-mail
		$a_01_2 = {56 65 6c 73 6f 40 70 72 6f 74 6f 6e 6d 61 69 6c } //01 00  Velso@protonmail
		$a_01_3 = {76 65 6c 73 6f } //01 00  velso
		$a_01_4 = {4e 53 74 37 5f 5f 63 78 78 31 31 31 30 6d 6f 6e 65 79 70 75 6e 63 74 49 63 4c 62 30 45 45 45 } //01 00  NSt7__cxx1110moneypunctIcLb0EEE
		$a_01_5 = {4e 53 74 37 5f 5f 63 78 78 31 31 31 34 63 6f 6c 6c 61 74 65 5f 62 79 6e 61 6d 65 49 63 45 45 } //00 00  NSt7__cxx1114collate_bynameIcEE
	condition:
		any of ($a_*)
 
}