
rule Trojan_BAT_Zilla_ZYT_MTB{
	meta:
		description = "Trojan:BAT/Zilla.ZYT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {03 1f 64 5a 06 6f ?? 00 00 0a 5b 5a 1f 64 5b 0c 03 03 1f 64 5a 06 6f ?? 00 00 0a 5b 03 5a 1f 64 5b 58 1f 64 58 0d 06 09 08 } //6
		$a_03_1 = {20 b1 04 00 00 28 ?? 00 00 0a 00 02 1c 28 ?? 00 00 0a 00 20 50 46 } //5
		$a_80_2 = {53 4f 5f 46 54 5f 57 5f 41 52 5f 45 5c 4d 69 5f 63 72 5f 6f 5f 73 6f 5f 66 5f 74 5c 57 5f 69 6e 5f 64 6f 5f 77 5f 73 5c 43 5f 75 5f 72 72 5f 65 6e 5f 74 56 5f 65 72 5f 73 5f 69 6f 6e 5c 52 5f 75 5f 6e } //SO_FT_W_AR_E\Mi_cr_o_so_f_t\W_in_do_w_s\C_u_rr_en_tV_er_s_ion\R_u_n  1
		$a_80_3 = {70 72 5f 6f 67 72 5f 61 6d 20 66 69 6c 65 73 20 28 78 38 5f 36 29 } //pr_ogr_am files (x8_6)  1
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=13
 
}