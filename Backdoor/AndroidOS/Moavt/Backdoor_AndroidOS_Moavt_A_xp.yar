
rule Backdoor_AndroidOS_Moavt_A_xp{
	meta:
		description = "Backdoor:AndroidOS/Moavt.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {48 74 74 70 33 30 32 65 6e 64 00 4b 48 } //1
		$a_00_1 = {69 50 69 6e 46 61 6e 00 4b 53 65 72 76 65 72 43 6c 6f 73 } //1
		$a_00_2 = {6c 65 70 68 6f 6e 79 2f 63 61 72 72 69 65 72 73 00 61 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}