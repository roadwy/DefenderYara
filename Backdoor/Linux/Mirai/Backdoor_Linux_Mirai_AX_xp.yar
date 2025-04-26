
rule Backdoor_Linux_Mirai_AX_xp{
	meta:
		description = "Backdoor:Linux/Mirai.AX!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 07 00 00 "
		
	strings :
		$a_00_0 = {72 6d 20 2d 72 66 20 2f 62 69 6e 2f 6e 65 74 73 74 61 74 } //1 rm -rf /bin/netstat
		$a_00_1 = {70 6b 69 6c 6c 20 2d 39 20 62 75 73 79 62 6f 78 } //1 pkill -9 busybox
		$a_00_2 = {2f 2e 62 61 73 68 5f 68 69 73 74 6f 72 79 } //1 /.bash_history
		$a_00_3 = {73 65 72 76 69 63 65 20 66 69 72 65 77 61 6c 6c 64 20 73 74 6f 70 } //1 service firewalld stop
		$a_00_4 = {bd 27 00 00 be af 21 f0 a0 03 1c 80 82 8f 00 00 00 00 64 1f 42 24 21 e8 c0 03 00 00 be 8f 08 00 bd } //1
		$a_00_5 = {6e 3c 02 3c 72 f3 42 34 21 18 62 00 18 80 82 8f 00 00 } //1
		$a_00_6 = {42 24 08 00 43 ac 03 00 02 24 08 00 c2 af 23 00 00 10 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=3
 
}