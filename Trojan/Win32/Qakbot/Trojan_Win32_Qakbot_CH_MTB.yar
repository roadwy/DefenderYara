
rule Trojan_Win32_Qakbot_CH_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_01_0 = {4a 5f 67 6d 70 5f 6c 69 6d 62 72 6f 6f 74 73 5f 74 61 62 6c 65 } //1 J_gmp_limbroots_table
		$a_01_1 = {4a 5f 67 6d 70 5f 70 72 69 6d 65 73 69 65 76 65 } //1 J_gmp_primesieve
		$a_01_2 = {4a 5f 67 6d 70 5f 64 65 66 61 75 6c 74 5f 66 70 5f 6c 69 6d 62 5f 70 72 65 63 69 73 69 6f 6e } //1 J_gmp_default_fp_limb_precision
		$a_01_3 = {4a 5f 67 6d 70 5f 61 73 70 72 69 6e 74 66 5f 6d 65 6d 6f 72 79 } //1 J_gmp_asprintf_memory
		$a_01_4 = {4a 5f 67 6d 70 5f 72 61 6e 64 73 5f 69 6e 69 74 69 61 6c 69 7a 65 64 } //1 J_gmp_rands_initialized
		$a_01_5 = {4a 5f 67 6d 70 5f 74 6d 70 5f 72 65 65 6e 74 72 61 6e 74 5f 61 6c 6c 6f 63 } //1 J_gmp_tmp_reentrant_alloc
		$a_01_6 = {4a 5f 67 6d 70 5f 75 72 61 6e 64 6f 6d 6d 5f 75 69 } //1 J_gmp_urandomm_ui
		$a_01_7 = {4a 5f 67 6d 70 66 5f 66 69 74 73 5f 73 6c 6f 6e 67 5f 70 } //1 J_gmpf_fits_slong_p
		$a_01_8 = {4a 5f 67 6d 70 66 5f 67 65 74 5f 64 65 66 61 75 6c 74 5f 70 72 65 63 } //1 J_gmpf_get_default_prec
		$a_01_9 = {4a 5f 67 6d 70 66 5f 75 72 61 6e 64 6f 6d 62 } //1 J_gmpf_urandomb
		$a_01_10 = {4a 5f 67 6d 70 6e 5f 61 64 64 6d 75 6c 5f 31 5f 70 36 5f 73 73 65 32 } //1 J_gmpn_addmul_1_p6_sse2
		$a_01_11 = {4a 5f 67 6d 70 6e 5f 62 63 5f 6d 75 6c 6d 6f 64 5f 62 6e 6d 31 } //1 J_gmpn_bc_mulmod_bnm1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=12
 
}