
rule Backdoor_Linux_Mirai_R_xp{
	meta:
		description = "Backdoor:Linux/Mirai.R!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 77 67 65 74 20 2d 67 20 31 34 36 2e 31 39 36 2e 36 37 2e 36 31 20 2d 6c 20 2f 74 6d 70 2f 6d 6f 6e 6b 65 20 2d 72 20 2f 75 } //1 /bin/busybox wget -g 146.196.67.61 -l /tmp/monke -r /u
		$a_00_1 = {2f 74 6d 70 2f 6d 6f 6e 6b 65 20 73 65 6c 66 72 65 70 2e 72 6f 75 74 65 72 } //1 /tmp/monke selfrep.router
		$a_00_2 = {78 38 45 2f 78 39 46 2f 78 44 39 2f 78 38 31 2f 78 38 33 2f 78 39 39 } //1 x8E/x9F/xD9/x81/x83/x99
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}