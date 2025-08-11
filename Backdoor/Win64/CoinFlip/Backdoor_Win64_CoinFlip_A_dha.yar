
rule Backdoor_Win64_CoinFlip_A_dha{
	meta:
		description = "Backdoor:Win64/CoinFlip.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 09 00 00 "
		
	strings :
		$a_01_0 = {73 72 63 5c 63 68 61 6e 67 65 62 61 63 6b 75 70 2e 72 73 } //1 src\changebackup.rs
		$a_01_1 = {73 72 63 5c 73 63 72 65 65 6e 73 68 6f 74 2e 72 73 } //1 src\screenshot.rs
		$a_01_2 = {73 72 63 5c 74 61 73 6b 6c 69 73 74 2e 72 73 } //1 src\tasklist.rs
		$a_01_3 = {73 72 63 5c 75 70 6c 6f 61 64 5f 66 69 6c 65 2e 72 73 } //1 src\upload_file.rs
		$a_01_4 = {73 72 63 5c 64 6e 73 68 6f 73 74 6e 61 6d 65 2e 72 73 } //1 src\dnshostname.rs
		$a_01_5 = {73 72 63 5c 64 6f 77 6e 6c 6f 61 64 66 69 6c 65 2e 72 73 } //1 src\downloadfile.rs
		$a_01_6 = {73 72 63 5c 69 70 63 6f 6e 66 69 67 2e 72 73 } //1 src\ipconfig.rs
		$a_01_7 = {73 72 63 5c 6b 69 6c 6c 70 72 6f 67 72 61 6d 2e 72 73 } //1 src\killprogram.rs
		$a_01_8 = {73 72 63 5c 72 75 6e 63 6f 6d 6d 61 6e 64 2e 72 73 } //1 src\runcommand.rs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=5
 
}