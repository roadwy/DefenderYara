
rule Backdoor_Linux_Gafgyt_BM_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.BM!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {4c 4f 43 4b 4c 55 53 45 52 53 } //1 LOCKLUSERS
		$a_01_1 = {67 6f 74 5f 6e 69 63 6b 76 32 } //1 got_nickv2
		$a_01_2 = {4b 49 4c 4c 54 41 4c 45 50 } //1 KILLTALEP
		$a_01_3 = {64 6f 5f 62 6f 74 6b 69 6c 6c } //1 do_botkill
		$a_01_4 = {64 6f 5f 73 65 6e 64 5f 73 76 73 74 69 6d 65 } //1 do_send_svstime
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}