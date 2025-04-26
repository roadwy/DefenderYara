
rule Backdoor_Linux_Mirai_D_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,0d 00 0d 00 08 00 00 "
		
	strings :
		$a_00_0 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 43 4f 52 4f 4e 41 } //10 /bin/busybox CORONA
		$a_00_1 = {ae 39 2e e0 02 30 23 e0 22 c4 23 e0 ff 10 0c e2 2c 28 a0 e1 2c 34 a0 e1 00 00 51 e3 7f 00 51 13 ff 60 02 e2 ff 00 03 e2 2c 2c a0 e1 } //2
		$a_00_2 = {68 75 6e 74 35 37 35 39 } //1 hunt5759
		$a_00_3 = {74 73 67 6f 69 6e 67 6f 6e } //1 tsgoingon
		$a_00_4 = {78 6d 68 64 69 70 63 } //1 xmhdipc
		$a_00_5 = {73 79 6e 6e 65 74 } //1 synnet
		$a_00_6 = {65 70 69 63 72 6f 75 74 65 } //1 epicroute
		$a_00_7 = {74 65 6c 65 63 6f 6d 61 64 6d 69 6e } //1 telecomadmin
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=13
 
}
rule Backdoor_Linux_Mirai_D_MTB_2{
	meta:
		description = "Backdoor:Linux/Mirai.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {2f 65 74 63 2f 63 72 6f 6e 74 61 62 2f 72 6f 6f 74 } //1 /etc/crontab/root
		$a_00_1 = {72 6d 20 2d 72 66 20 6c 6f 6c 6f 6c 2e 73 68 } //1 rm -rf lolol.sh
		$a_02_2 = {62 75 73 79 62 6f 78 20 77 67 65 74 20 68 74 74 70 [0-08] 2e [0-03] 2e [0-03] 2e ?? ?? 2f 6c 6f 6c 6f 6c 2e 73 68 } //1
		$a_02_3 = {73 68 65 6c 6c 20 63 64 20 2f 74 6d 70 3b 20 77 67 65 74 20 68 74 74 70 [0-08] 2e [0-03] 2e [0-03] 2e ?? ?? 2f 6c 6f 6c 6f 6c 2e 73 68 3b 20 63 68 6d 6f 64 20 37 37 37 20 6c 6f 6c 6f 6c 2e 73 68 3b 20 73 68 20 6c 6f 6c 6f 6c 2e 73 68 } //1
		$a_00_4 = {62 61 63 6b 75 70 6d 67 74 2f 6c 6f 63 61 6c 4a 6f 62 2e 70 68 70 } //1 backupmgt/localJob.php
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}