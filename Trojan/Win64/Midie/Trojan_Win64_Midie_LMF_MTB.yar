
rule Trojan_Win64_Midie_LMF_MTB{
	meta:
		description = "Trojan:Win64/Midie.LMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,24 00 24 00 08 00 00 "
		
	strings :
		$a_81_0 = {5f 62 69 6e 64 5f 6d 67 72 5f 38 37 37 35 } //1 _bind_mgr_8775
		$a_81_1 = {63 72 65 61 74 65 5f 64 61 74 61 5f 32 35 } //2 create_data_25
		$a_81_2 = {63 72 65 61 74 65 5f 69 6e 66 6f 5f 39 37 } //3 create_info_97
		$a_81_3 = {6c 6f 61 64 5f 68 61 6e 64 6c 65 5f 33 } //4 load_handle_3
		$a_81_4 = {6f 70 65 6e 5f 64 61 74 61 5f 35 35 } //5 open_data_55
		$a_81_5 = {70 72 6f 63 65 73 73 5f 68 61 6e 64 6c 65 5f 36 37 } //6 process_handle_67
		$a_81_6 = {73 65 74 5f 69 6e 66 6f 5f 32 33 } //7 set_info_23
		$a_81_7 = {73 74 61 72 74 5f 63 61 63 68 65 5f 37 36 } //8 start_cache_76
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*2+(#a_81_2  & 1)*3+(#a_81_3  & 1)*4+(#a_81_4  & 1)*5+(#a_81_5  & 1)*6+(#a_81_6  & 1)*7+(#a_81_7  & 1)*8) >=36
 
}