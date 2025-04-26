
rule Backdoor_Linux_Mirai_DI_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.DI!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {6d 65 64 75 73 61 2d 73 74 65 61 6c 65 72 2e 63 63 } //1 medusa-stealer.cc
		$a_00_1 = {6d 65 64 75 73 61 5f 63 6e 63 } //1 medusa_cnc
		$a_00_2 = {73 63 72 61 70 65 5f 64 61 74 61 } //1 scrape_data
		$a_00_3 = {75 64 70 5f 66 6c 6f 6f 64 } //1 udp_flood
		$a_00_4 = {73 70 6f 6f 66 65 72 5f 70 72 6f 63 65 73 73 5f 6e 61 6d 65 } //1 spoofer_process_name
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}