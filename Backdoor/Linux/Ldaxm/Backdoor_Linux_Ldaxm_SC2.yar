
rule Backdoor_Linux_Ldaxm_SC2{
	meta:
		description = "Backdoor:Linux/Ldaxm.SC2,SIGNATURE_TYPE_CMDHSTR_EXT,28 00 28 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 00 75 00 72 00 6c 00 20 00 } //10 curl 
		$a_00_1 = {2d 00 6f 00 20 00 2f 00 74 00 6d 00 70 00 2f 00 } //10 -o /tmp/
		$a_00_2 = {6e 00 6f 00 68 00 75 00 70 00 20 00 70 00 79 00 74 00 68 00 6f 00 6e 00 33 00 20 00 2f 00 74 00 6d 00 70 00 2f 00 } //10 nohup python3 /tmp/
		$a_00_3 = {2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 } //10 /dev/null
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=40
 
}