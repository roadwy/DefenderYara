
rule Trojan_AndroidOS_Evilinst_C{
	meta:
		description = "Trojan:AndroidOS/Evilinst.C,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 65 72 66 6f 72 6d 41 64 73 53 65 6e 73 } //2 PerformAdsSens
		$a_01_1 = {61 6e 6f 74 68 65 72 5f 67 69 72 6c 5f 69 6e 5f 74 68 65 5f 77 61 6c 6c 5f 66 62 } //2 another_girl_in_the_wall_fb
		$a_01_2 = {53 41 56 45 5f 50 45 52 5f 50 55 53 48 5f 4a 4f 42 } //2 SAVE_PER_PUSH_JOB
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=4
 
}