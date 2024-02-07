
rule Trojan_Win32_Fareit_RW_MTB{
	meta:
		description = "Trojan:Win32/Fareit.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 7c 30 fc 90 02 0f 5d 90 02 0a 81 f7 90 02 12 57 90 02 0a 8f 44 30 fc 90 02 19 d9 90 00 } //01 00 
		$a_03_1 = {8b 7c 10 fc 90 02 0f 5d 90 02 0a 81 f7 90 02 12 57 90 02 0a 8f 44 10 fc 90 02 19 d9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fareit_RW_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {56 5f 69 5f 72 5f 74 5f 75 5f 61 5f 6c 5f 50 5f 72 5f 6f 5f 74 5f 65 5f 63 5f 74 5f } //01 00  V_i_r_t_u_a_l_P_r_o_t_e_c_t_
		$a_81_1 = {43 32 72 32 79 32 70 32 74 32 44 32 65 32 73 32 74 32 72 32 6f 32 79 32 4b 32 65 32 79 32 } //01 00  C2r2y2p2t2D2e2s2t2r2o2y2K2e2y2
		$a_81_2 = {56 44 69 44 72 44 74 44 75 44 61 44 6c 44 41 44 6c 44 6c 44 6f 44 63 44 45 44 78 44 } //01 00  VDiDrDtDuDaDlDADlDlDoDcDEDxD
		$a_81_3 = {6f 77 65 64 6d 65 73 61 } //00 00  owedmesa
	condition:
		any of ($a_*)
 
}