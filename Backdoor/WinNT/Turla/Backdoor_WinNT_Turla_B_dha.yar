
rule Backdoor_WinNT_Turla_B_dha{
	meta:
		description = "Backdoor:WinNT/Turla.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {74 6f 6b 65 6e 5f 76 61 6c } //1 token_val
		$a_01_1 = {66 00 69 00 6c 00 74 00 65 00 72 00 5f 00 63 00 30 00 36 00 62 00 31 00 61 00 33 00 62 00 } //1 filter_c06b1a3b
		$a_00_2 = {4e 64 69 73 46 52 65 67 69 73 74 65 72 46 69 6c 74 65 72 44 72 69 76 65 72 } //1 NdisFRegisterFilterDriver
		$a_00_3 = {46 77 70 73 53 74 72 65 61 6d 49 6e 6a 65 63 74 41 73 79 6e 63 30 } //1 FwpsStreamInjectAsync0
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}