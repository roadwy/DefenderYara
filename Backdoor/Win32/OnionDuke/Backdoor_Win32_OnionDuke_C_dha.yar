
rule Backdoor_Win32_OnionDuke_C_dha{
	meta:
		description = "Backdoor:Win32/OnionDuke.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {75 70 6c 6f 61 64 5f 73 6c 6f 77 64 6f 77 6e 5f 6d 73 3a } //1 upload_slowdown_ms:
		$a_01_1 = {6d 61 73 74 65 72 5f 73 6c 61 76 65 5f 70 6f 6c 69 63 79 3a } //1 master_slave_policy:
		$a_01_2 = {70 6f 73 74 5f 70 65 72 5f 72 65 71 75 65 73 74 5f 6c 69 6d 69 74 5f 6b 62 3a } //1 post_per_request_limit_kb:
		$a_01_3 = {6c 6f 63 61 6c 5f 6c 69 6d 69 74 5f 6d 62 3a } //1 local_limit_mb:
		$a_01_4 = {6d 79 63 65 72 74 3a 20 68 65 78 28 } //1 mycert: hex(
		$a_01_5 = {2d 20 61 72 67 3a 20 63 61 6d 70 61 69 67 6e 5f 69 64 } //1 - arg: campaign_id
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}