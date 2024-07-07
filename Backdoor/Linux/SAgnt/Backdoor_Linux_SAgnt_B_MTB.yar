
rule Backdoor_Linux_SAgnt_B_MTB{
	meta:
		description = "Backdoor:Linux/SAgnt.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 65 6c 5f 73 65 6e 64 5f 6d 73 67 } //1 pel_send_msg
		$a_01_1 = {65 78 65 63 20 62 61 73 68 20 2d 2d 6c 6f 67 69 6e } //1 exec bash --login
		$a_01_2 = {70 65 6c 5f 72 65 63 76 5f 6d 73 67 } //1 pel_recv_msg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}