
rule Backdoor_Linux_Hydgo_A_xp{
	meta:
		description = "Backdoor:Linux/Hydgo.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 79 64 72 6f 67 65 6e 5f 63 6c 69 65 6e 74 20 5b 2d 6c 20 70 6f 72 74 5d } //2 hydrogen_client [-l port]
		$a_01_1 = {68 63 6c 69 65 6e 74 5f 6c 6f 6f 70 2e 63 } //2 hclient_loop.c
		$a_01_2 = {70 66 5f 73 74 61 72 74 5f 6f 75 74 5f 74 63 70 } //1 pf_start_out_tcp
		$a_01_3 = {2f 74 6d 70 2f 68 6c 6f 67 2e 74 78 74 } //1 /tmp/hlog.txt
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}