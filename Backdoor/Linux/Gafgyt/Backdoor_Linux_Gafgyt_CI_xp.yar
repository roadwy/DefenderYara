
rule Backdoor_Linux_Gafgyt_CI_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.CI!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_00_0 = {6b 69 6c 6c 20 2d 39 20 24 28 70 69 64 6f 66 20 62 75 73 79 62 6f 78 } //1 kill -9 $(pidof busybox
		$a_00_1 = {2f 75 73 72 2f 73 62 69 6e 2f 64 72 6f 70 62 65 61 72 } //1 /usr/sbin/dropbear
		$a_00_2 = {62 75 73 79 62 6f 78 20 74 66 74 70 20 2d 72 20 74 66 74 70 32 2e 73 68 20 2d 67 } //1 busybox tftp -r tftp2.sh -g
		$a_00_3 = {c7 85 9c fd ff ff 89 02 12 80 8b 85 9c fd ff ff f7 e9 8d 04 0a 89 c2 c1 fa 0f 89 c8 c1 f8 1f } //1
		$a_00_4 = {29 c3 89 d8 89 45 c0 8b 45 c0 69 c0 dc ff 00 00 89 ca 29 c2 89 d0 } //1
		$a_00_5 = {89 45 c0 c7 45 bc 01 00 00 00 48 8d bd 60 ff ff ff be e0 33 41 00 ba 54 00 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=3
 
}