
rule Trojan_Win32_Maptrepol_A{
	meta:
		description = "Trojan:Win32/Maptrepol.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {6e 00 5f 00 6d 00 74 00 74 00 72 00 5f 00 70 00 70 00 6c 00 5f 00 77 00 68 00 74 00 73 00 73 00 5f 00 79 00 5f 00 73 00 79 00 } //2 n_mttr_ppl_whtss_y_sy
		$a_01_1 = {57 72 6c 63 6b 2e 64 6c 6c } //2 Wrlck.dll
		$a_01_2 = {50 72 73 74 2e 64 6c 6c } //2 Prst.dll
		$a_01_3 = {5c 73 74 61 72 74 65 72 2e 70 64 62 } //1 \starter.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=5
 
}