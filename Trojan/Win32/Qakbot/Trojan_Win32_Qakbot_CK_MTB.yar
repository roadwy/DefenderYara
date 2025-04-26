
rule Trojan_Win32_Qakbot_CK_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.CK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 0c 10 8d 1c 0f 83 e3 ?? 8a 9b ?? ?? ?? 00 32 1c 16 42 88 19 3b 55 fc 72 e6 } //1
		$a_03_1 = {8b d1 83 e2 ?? 8a 92 ?? ?? ?? 00 32 14 08 74 07 41 3b ce 72 eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qakbot_CK_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.CK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {49 5f 67 6d 70 5f 62 69 6e 76 65 72 74 5f 6c 69 6d 62 5f 74 61 62 6c 65 } //1 I_gmp_binvert_limb_table
		$a_01_1 = {49 5f 67 6d 70 5f 64 65 66 61 75 6c 74 5f 66 70 5f 6c 69 6d 62 5f 70 72 65 63 69 73 69 6f 6e } //1 I_gmp_default_fp_limb_precision
		$a_01_2 = {49 5f 67 6d 70 5f 6a 61 63 6f 62 69 5f 74 61 62 6c 65 } //1 I_gmp_jacobi_table
		$a_01_3 = {49 5f 67 6d 70 5f 6d 74 5f 72 65 63 61 6c 63 5f 62 75 66 66 65 72 } //1 I_gmp_mt_recalc_buffer
		$a_01_4 = {49 5f 67 6d 70 6e 5f 6e 75 73 73 62 61 75 6d 65 72 5f 6d 75 6c } //1 I_gmpn_nussbaumer_mul
		$a_01_5 = {49 5f 67 6d 70 6e 5f 72 73 68 69 66 74 5f 6b 36 5f 6b 36 32 6d 6d 78 } //1 I_gmpn_rshift_k6_k62mmx
		$a_01_6 = {49 5f 67 6d 70 6e 5f 73 74 72 6f 6e 67 66 69 62 6f } //1 I_gmpn_strongfibo
		$a_01_7 = {49 5f 67 6d 70 6e 5f 73 75 62 6d 75 6c 5f 31 63 5f 70 65 6e 74 69 75 6d 34 5f 73 73 65 32 } //1 I_gmpn_submul_1c_pentium4_sse2
		$a_01_8 = {49 5f 67 6d 70 6e 5f 74 6f 6f 6d 5f 63 6f 75 70 6c 65 5f 68 61 6e 64 6c 69 6e 67 } //1 I_gmpn_toom_couple_handling
		$a_01_9 = {49 5f 67 6d 70 7a 5f 6d 69 6c 6c 65 72 72 61 62 69 6e } //1 I_gmpz_millerrabin
		$a_01_10 = {49 5f 67 6d 70 7a 5f 74 64 69 76 5f 72 5f 32 65 78 70 } //1 I_gmpz_tdiv_r_2exp
		$a_01_11 = {49 5f 67 6d 70 7a 5f 75 69 5f 6b 72 6f 6e 65 63 6b 65 72 } //1 I_gmpz_ui_kronecker
		$a_01_12 = {4e 69 6b 6e } //1 Nikn
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=13
 
}