
rule Trojan_Linux_Mirai_HH{
	meta:
		description = "Trojan:Linux/Mirai.HH,SIGNATURE_TYPE_ELFHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 76 61 72 2f 53 6f 66 69 61 2f } //5 /var/Sofia/
		$a_00_1 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 64 64 20 69 66 3d 2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 62 73 3d } //3 /bin/busybox dd if=/bin/busybox bs=
		$a_00_2 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 63 68 6d 6f 64 20 37 37 37 } //2 /bin/busybox chmod 777
		$a_00_3 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 63 61 74 20 2f 70 72 6f 63 2f 63 70 75 69 6e 66 6f } //2 /bin/busybox cat /proc/cpuinfo
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*3+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=10
 
}