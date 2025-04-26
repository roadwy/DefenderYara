
rule Backdoor_Linux_Mirai_AZ_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.AZ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {62 6f 74 20 25 73 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 64 65 70 6c 6f 79 65 64 20 76 69 61 20 65 63 68 6f 20 2d 2d 2d 3e 20 5b 25 73 3a 25 64 20 25 73 3a 25 73 } //1 bot %s successfully deployed via echo ---> [%s:%d %s:%s
		$a_00_1 = {62 69 6e 2f 62 75 73 79 62 6f 78 20 63 68 6d 6f 64 20 37 37 37 20 25 73 3b 20 2e 2f 25 73 20 74 65 6c 6e 65 74 2e 25 73 2e 77 67 65 74 } //1 bin/busybox chmod 777 %s; ./%s telnet.%s.wget
		$a_00_2 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 63 68 6d 6f 64 20 37 37 37 20 25 73 3b 20 2e 2f 25 73 20 74 65 6c 6e 65 74 2e 25 73 2e 74 66 74 70 } //1 /bin/busybox chmod 777 %s; ./%s telnet.%s.tftp
		$a_00_3 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 65 63 68 6f 20 2d 65 6e 20 27 25 73 27 20 25 73 20 25 73 20 26 26 20 2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 65 63 68 6f 20 2d 65 6e 20 27 5c 78 34 35 5c 78 34 33 5c 78 34 38 5c 78 34 66 5c 78 34 34 5c 78 34 66 5c 78 34 65 5c 78 34 35 } //1 /bin/busybox echo -en '%s' %s %s && /bin/busybox echo -en '\x45\x43\x48\x4f\x44\x4f\x4e\x45
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}