
rule Trojan_Win32_Refpron{
	meta:
		description = "Trojan:Win32/Refpron,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 4d e8 66 ba 88 2e b8 90 01 02 00 10 e8 90 01 02 ff ff 8b 4d e8 8b 15 90 01 02 00 10 8b 12 8d 45 ec e8 90 00 } //01 00 
		$a_03_1 = {89 45 fc 8d 4d f8 66 ba 88 2e b8 90 01 02 00 10 e8 90 01 02 ff ff 33 c0 55 68 90 00 } //02 00 
		$a_00_2 = {4d 79 5f 4d 5f 69 5f 6e 69 54 5f 43 5f 50 43 5f 6c 69 65 6e 74 } //02 00  My_M_i_niT_C_PC_lient
		$a_00_3 = {65 5f 72 5f 72 5f } //00 00  e_r_r_
	condition:
		any of ($a_*)
 
}