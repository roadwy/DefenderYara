
rule Backdoor_Linux_Mirai_CJ_xp{
	meta:
		description = "Backdoor:Linux/Mirai.CJ!xp,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 63 68 6d 6f 64 20 37 37 37 } //1 /bin/busybox chmod 777
		$a_00_1 = {72 6d 20 72 66 20 43 72 6f 6e 75 73 6d 69 70 73 29 } //1 rm rf Cronusmips)
		$a_00_2 = {2f 72 6f 6f 74 2f 64 76 72 5f 67 75 69 2f } //1 /root/dvr_gui/
		$a_00_3 = {2f 75 73 72 2f 62 69 6e 2f 6e 6c 6f 61 64 } //1 /usr/bin/nload
		$a_00_4 = {33 2e 31 33 36 2e 34 31 2e 31 31 31 20 } //1 3.136.41.111 
		$a_00_5 = {00 75 92 12 61 20 40 00 00 ac } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}