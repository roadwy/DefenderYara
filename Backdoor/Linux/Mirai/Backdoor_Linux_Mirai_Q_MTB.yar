
rule Backdoor_Linux_Mirai_Q_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.Q!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 68 6d 6f 64 2b 37 37 37 2b 6c 6f 6c 6f 6c 2e 73 68 } //1 chmod+777+lolol.sh
		$a_00_1 = {2f 62 61 63 6b 75 70 6d 67 74 2f 6c 6f 63 61 6c 4a 6f 62 2e 70 68 70 } //1 /backupmgt/localJob.php
		$a_00_2 = {73 68 2b 6c 6f 6c 6f 6c 2e 73 68 } //1 sh+lolol.sh
		$a_03_3 = {77 67 65 74 2b 68 74 74 70 [0-20] 2f 6c 6f 6c 6f 6c 2e 73 68 } //1
		$a_03_4 = {63 75 72 6c 2b 2d 4f ?? ?? 68 74 74 70 [0-20] 2f 6c 6f 6c 6f 6c 2e 73 68 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}