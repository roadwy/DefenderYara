
rule Trojan_Linux_Mirai_MTB{
	meta:
		description = "Trojan:Linux/Mirai!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 45 53 54 45 4c 4c 41 } //01 00  /bin/busybox ESTELLA
		$a_00_1 = {63 68 6d 6f 64 20 37 37 37 20 2e 6c 6f 61 64 3b } //01 00  chmod 777 .load;
		$a_00_2 = {6b 69 6c 6c 61 6c 6c 20 2d 39 20 62 75 73 79 62 6f 78 20 74 65 6c 6e 65 74 64 } //01 00  killall -9 busybox telnetd
		$a_00_3 = {65 63 68 6f 20 2d 65 20 22 2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 74 65 6c 6e 65 74 64 20 2d 70 39 30 30 30 20 2d 6c 2f 62 69 6e 2f 73 68 } //00 00  echo -e "/bin/busybox telnetd -p9000 -l/bin/sh
	condition:
		any of ($a_*)
 
}