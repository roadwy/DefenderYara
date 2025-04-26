
rule Backdoor_Linux_Mirai_AJ_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.AJ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 64 20 2f 74 6d 70 2f 7c 7c 63 64 20 2f 75 73 72 2f 73 62 69 6e 7c 7c 63 64 20 2f 76 61 72 2f 74 6d 70 3b } //1 cd /tmp/||cd /usr/sbin||cd /var/tmp;
		$a_00_1 = {77 67 65 74 20 90 01 04 3a 2f 2f 65 76 30 6c 76 65 2e 63 66 2f 61 72 6d 20 7c 7c 20 20 2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 74 66 74 70 20 2d 67 20 65 76 30 6c 76 65 2e 63 66 20 2d 72 20 61 72 6d } //1
		$a_00_2 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 63 68 6d 6f 64 20 37 37 37 20 61 72 6d 3b 2e 2f 61 72 6d 20 73 65 6c 66 2e 64 6f 77 6e 6c 6f 61 64 20 7c 7c 20 72 6d 20 61 72 6d 20 2d 72 66 } //1 /bin/busybox chmod 777 arm;./arm self.download || rm arm -rf
		$a_00_3 = {63 68 6d 6f 64 20 2b 78 20 6d 70 73 6c 20 3b 20 2e 2f 6d 70 73 6c 20 73 65 6c 66 2e 64 6f 77 6e 6c 6f 61 64 } //1 chmod +x mpsl ; ./mpsl self.download
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}