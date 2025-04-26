
rule Trojan_MacOS_KandyKorn_A_MTB{
	meta:
		description = "Trojan:MacOS/KandyKorn.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {72 65 73 70 5f 66 69 6c 65 5f 64 69 72 } //1 resp_file_dir
		$a_00_1 = {72 65 73 70 5f 63 66 67 5f 73 65 74 } //1 resp_cfg_set
		$a_00_2 = {72 65 73 70 5f 70 72 6f 63 5f 6b 69 6c 6c } //1 resp_proc_kill
		$a_00_3 = {2f 63 6f 6d 2e 61 70 70 6c 65 2e 73 61 66 61 72 69 2e 63 6b } //1 /com.apple.safari.ck
		$a_00_4 = {63 75 72 6c 5f 65 61 73 79 5f 67 65 74 69 6e 66 6f } //1 curl_easy_getinfo
		$a_00_5 = {2f 63 68 6b 75 70 64 61 74 65 2e 78 78 78 } //1 /chkupdate.xxx
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}