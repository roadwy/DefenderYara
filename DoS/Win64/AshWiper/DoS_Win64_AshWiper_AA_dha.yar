
rule DoS_Win64_AshWiper_AA_dha{
	meta:
		description = "DoS:Win64/AshWiper.AA!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6c 69 73 74 5f 64 69 73 6b } //1 list_disk
		$a_01_1 = {64 65 73 74 72 6f 79 5f 66 69 6c 65 } //1 destroy_file
		$a_01_2 = {6c 69 73 74 46 69 6c 65 73 } //1 listFiles
		$a_01_3 = {6d 65 72 73 65 6e 6e 65 5f 74 77 69 73 74 65 72 5f 65 6e 67 69 6e 65 } //1 mersenne_twister_engine
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}