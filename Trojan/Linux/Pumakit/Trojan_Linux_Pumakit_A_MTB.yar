
rule Trojan_Linux_Pumakit_A_MTB{
	meta:
		description = "Trojan:Linux/Pumakit.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {50 55 4d 41 20 25 73 } //2 PUMA %s
		$a_01_1 = {4b 69 74 73 75 6e 65 20 50 49 44 20 25 6c 64 } //2 Kitsune PID %ld
		$a_01_2 = {2e 70 75 6d 61 2d 63 6f 6e 66 69 67 } //2 .puma-config
		$a_01_3 = {7a 61 72 79 61 } //2 zarya
		$a_01_4 = {6b 69 74 5f 73 6f 5f 6c 65 6e } //2 kit_so_len
		$a_01_5 = {2f 75 73 72 2f 73 68 61 72 65 2f 7a 6f 76 5f 66 } //1 /usr/share/zov_f
		$a_01_6 = {70 69 6e 67 5f 69 6e 74 65 72 76 61 6c 5f 73 } //1 ping_interval_s
		$a_01_7 = {73 65 73 73 69 6f 6e 5f 74 69 6d 65 6f 75 74 5f 73 } //1 session_timeout_s
		$a_01_8 = {63 32 5f 74 69 6d 65 6f 75 74 5f 73 } //1 c2_timeout_s
		$a_01_9 = {4c 44 5f 50 52 45 4c 4f 41 44 3d 2f 6c 69 62 36 34 2f 6c 69 62 73 2e 73 6f } //1 LD_PRELOAD=/lib64/libs.so
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}