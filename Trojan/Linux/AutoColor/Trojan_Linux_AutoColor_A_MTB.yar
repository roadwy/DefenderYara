
rule Trojan_Linux_AutoColor_A_MTB{
	meta:
		description = "Trojan:Linux/AutoColor.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 75 74 6f 2d 63 6f 6c 6f 72 } //2 auto-color
		$a_01_1 = {2f 64 6f 6f 72 2d 25 64 2e 6c 6f 67 } //2 /door-%d.log
		$a_01_2 = {2f 70 72 6f 63 2f 6e 65 74 2f 74 63 70 } //1 /proc/net/tcp
		$a_01_3 = {2f 65 74 63 2f 6c 64 2e 73 6f 2e 70 72 65 6c 6f 61 64 2e 78 78 78 } //1 /etc/ld.so.preload.xxx
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}