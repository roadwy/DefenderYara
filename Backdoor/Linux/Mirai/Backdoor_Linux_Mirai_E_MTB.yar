
rule Backdoor_Linux_Mirai_E_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.E!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 68 6d 6f 64 20 37 37 37 20 2a 20 2f 74 6d 70 2f 73 6b 65 72 65 } //2 chmod 777 * /tmp/skere
		$a_00_1 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 } //2 /bin/busybox
		$a_00_2 = {2d 6c 20 2f 74 6d 70 2f 73 6b 65 72 65 20 2d 72 20 2f 39 31 31 2e 6d 69 70 73 } //1 -l /tmp/skere -r /911.mips
		$a_00_3 = {00 20 9e e5 02 30 dc e7 03 30 20 e0 02 30 cc e7 00 10 9e e5 01 30 dc e7 03 30 26 e0 01 30 cc e7 00 20 9e e5 02 30 dc e7 03 30 25 e0 02 30 cc e7 00 10 9e e5 01 30 dc e7 03 30 24 e0 01 30 cc e7 04 20 de e5 01 30 d7 e5 01 c0 8c e2 03 24 82 e1 0c 00 52 e1 e9 ff ff ca f0 80 bd e8 } //1
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}