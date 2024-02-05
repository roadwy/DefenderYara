
rule Ransom_Win32_MowareHFD_A_rsm{
	meta:
		description = "Ransom:Win32/MowareHFD.A!rsm,SIGNATURE_TYPE_PEHSTR_EXT,fffffff4 01 fffffff4 01 05 00 00 64 00 "
		
	strings :
		$a_01_0 = {4d 6f 57 61 72 65 5f 48 2e 46 2e 44 2e 4d 79 } //64 00 
		$a_01_1 = {5f 5f 45 4e 43 41 64 64 54 6f 4c 69 73 74 } //64 00 
		$a_01_2 = {48 00 46 00 44 00 2f 00 67 00 65 00 6e 00 2e 00 70 00 68 00 70 00 } //64 00 
		$a_01_3 = {4d 00 52 00 78 00 43 00 30 00 44 00 45 00 52 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 } //64 00 
		$a_01_4 = {4d 00 6f 00 57 00 61 00 72 00 65 00 20 00 48 00 2e 00 46 00 2e 00 44 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}