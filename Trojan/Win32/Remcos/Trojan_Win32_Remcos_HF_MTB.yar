
rule Trojan_Win32_Remcos_HF_MTB{
	meta:
		description = "Trojan:Win32/Remcos.HF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 53 72 53 79 53 70 53 74 53 41 53 63 53 71 53 75 53 69 53 72 53 65 53 43 53 6f 53 6e 53 74 53 65 53 78 53 74 53 41 53 } //01 00  CSrSySpStSAScSqSuSiSrSeSCSoSnStSeSxStSAS
		$a_81_1 = {52 2d 74 2d 6c 2d 44 2d 65 2d 63 2d 6f 2d 6d 2d 70 2d 72 2d 65 2d 73 2d 73 2d 42 2d 75 2d 66 2d 66 2d 65 2d 72 2d } //01 00  R-t-l-D-e-c-o-m-p-r-e-s-s-B-u-f-f-e-r-
		$a_81_2 = {56 5f 69 5f 72 5f 74 5f 75 5f 61 5f 6c 5f 50 5f 72 5f 6f 5f 74 5f 65 5f 63 5f 74 5f } //01 00  V_i_r_t_u_a_l_P_r_o_t_e_c_t_
		$a_81_3 = {47 56 65 56 74 56 54 56 69 56 63 56 6b 56 43 56 6f 56 75 56 6e 56 74 56 } //01 00  GVeVtVTViVcVkVCVoVuVnVtV
		$a_81_4 = {45 59 78 59 69 59 74 59 50 59 72 59 6f 59 63 59 65 59 73 59 73 59 } //01 00  EYxYiYtYPYrYoYcYeYsYsY
		$a_81_5 = {43 37 72 37 79 37 70 37 74 37 44 37 65 37 63 37 72 37 79 37 70 37 74 37 } //01 00  C7r7y7p7t7D7e7c7r7y7p7t7
		$a_81_6 = {5a 65 74 61 20 44 65 62 75 67 67 65 72 } //01 00  Zeta Debugger
		$a_81_7 = {52 6f 63 6b 20 44 65 62 75 67 67 65 72 } //00 00  Rock Debugger
	condition:
		any of ($a_*)
 
}