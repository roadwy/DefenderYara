
rule Backdoor_Win64_FreshCam_A_dha{
	meta:
		description = "Backdoor:Win64/FreshCam.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 72 63 5c 63 6f 6d 6d 61 6e 64 73 5c 73 65 6e 64 5f 63 6d 64 2e 72 73 20 } //1 src\commands\send_cmd.rs 
		$a_01_1 = {73 72 63 5c 63 6f 6d 6d 61 6e 64 73 5c 73 65 6e 64 5f 73 74 61 74 75 73 2e 72 73 } //1 src\commands\send_status.rs
		$a_01_2 = {73 72 63 5c 63 6f 6d 6d 61 6e 64 73 5c 75 70 6c 6f 61 64 5f 64 61 74 61 2e 72 73 } //1 src\commands\upload_data.rs
		$a_01_3 = {73 72 63 5c 63 6f 6d 6d 61 6e 64 73 5c 64 6f 77 6e 6c 6f 61 64 5f 64 61 74 61 2e 72 73 } //1 src\commands\download_data.rs
		$a_01_4 = {73 72 63 5c 63 6f 6d 6d 61 6e 64 73 5c 74 65 63 68 6e 69 63 61 6c 5f 63 6f 6d 6d 61 6e 64 2e 72 73 } //1 src\commands\technical_command.rs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}