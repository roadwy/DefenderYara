
rule Trojan_Win32_Fareit_RW_MTB{
	meta:
		description = "Trojan:Win32/Fareit.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 7c 30 fc [0-0f] 5d [0-0a] 81 f7 [0-12] 57 [0-0a] 8f 44 30 fc [0-19] d9 } //1
		$a_03_1 = {8b 7c 10 fc [0-0f] 5d [0-0a] 81 f7 [0-12] 57 [0-0a] 8f 44 10 fc [0-19] d9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Fareit_RW_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {56 5f 69 5f 72 5f 74 5f 75 5f 61 5f 6c 5f 50 5f 72 5f 6f 5f 74 5f 65 5f 63 5f 74 5f } //1 V_i_r_t_u_a_l_P_r_o_t_e_c_t_
		$a_81_1 = {43 32 72 32 79 32 70 32 74 32 44 32 65 32 73 32 74 32 72 32 6f 32 79 32 4b 32 65 32 79 32 } //1 C2r2y2p2t2D2e2s2t2r2o2y2K2e2y2
		$a_81_2 = {56 44 69 44 72 44 74 44 75 44 61 44 6c 44 41 44 6c 44 6c 44 6f 44 63 44 45 44 78 44 } //1 VDiDrDtDuDaDlDADlDlDoDcDEDxD
		$a_81_3 = {6f 77 65 64 6d 65 73 61 } //1 owedmesa
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}