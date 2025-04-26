
rule TrojanSpy_Win32_Maptrepol_A{
	meta:
		description = "TrojanSpy:Win32/Maptrepol.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {4e 00 5f 00 65 00 5f 00 77 00 5f 00 5f 00 64 00 65 00 5f 00 76 00 65 00 6e 00 5f 00 65 00 78 00 5f 00 6b 00 65 00 79 00 5f 00 72 00 5f 00 63 00 64 00 5f 00 31 00 } //2 N_e_w__de_ven_ex_key_r_cd_1
		$a_01_1 = {50 72 73 74 49 6e 64 2e 62 69 6e } //2 PrstInd.bin
		$a_01_2 = {5c 6b 65 79 6c 6f 67 67 65 72 2e 70 64 62 } //2 \keylogger.pdb
		$a_01_3 = {25 6c 73 6d 73 61 74 74 72 69 62 33 32 5f 25 73 5f 6b 5f 25 75 2e 72 65 73 } //2 %lsmsattrib32_%s_k_%u.res
		$a_01_4 = {70 72 73 74 2e 63 61 62 } //1 prst.cab
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=7
 
}