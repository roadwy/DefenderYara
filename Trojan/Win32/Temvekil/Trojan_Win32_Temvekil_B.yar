
rule Trojan_Win32_Temvekil_B{
	meta:
		description = "Trojan:Win32/Temvekil.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 75 6f 6d 6e 72 67 65 00 00 00 00 65 46 69 6c 65 57 } //1
		$a_01_1 = {5c 74 68 75 6d 62 6e 61 69 6c 73 2e 64 62 00 00 2e 00 74 00 6d 00 70 } //1
		$a_01_2 = {5f 4e 5f 75 5f 6c 5f 6c 5f 73 5f 6f 5f 66 5f 74 5f 49 5f 6e 5f 73 5f 74 5f } //1 _N_u_l_l_s_o_f_t_I_n_s_t_
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}