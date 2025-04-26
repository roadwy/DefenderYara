
rule Backdoor_Win64_FreshCam_B_dha{
	meta:
		description = "Backdoor:Win64/FreshCam.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 72 63 5c 63 6f 6d 6d 61 6e 64 73 5c 73 65 6e 64 5f 6f 6b 2e 72 73 } //1 src\commands\send_ok.rs
		$a_01_1 = {73 72 63 5c 63 6f 6d 6d 61 6e 64 73 5c 67 65 74 5f 64 61 74 61 2e 72 73 } //1 src\commands\get_data.rs
		$a_01_2 = {73 72 63 5c 63 6f 6d 6d 61 6e 64 73 5c 64 6f 5f 63 6f 6d 6d 61 6e 64 2e 72 73 } //1 src\commands\do_command.rs
		$a_01_3 = {73 72 63 5c 63 6f 6d 6d 61 6e 64 73 5c 73 65 6e 64 5f 64 61 74 61 2e 72 73 } //1 src\commands\send_data.rs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}