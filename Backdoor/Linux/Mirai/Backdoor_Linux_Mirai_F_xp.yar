
rule Backdoor_Linux_Mirai_F_xp{
	meta:
		description = "Backdoor:Linux/Mirai.F!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 75 72 65 6e 65 74 77 6f 72 6b 73 2e 63 6f 6d 2f 48 4e 41 50 31 2f } //1 purenetworks.com/HNAP1/
		$a_03_1 = {2f 74 6d 70 [0-11] 68 75 61 77 65 69 2e 65 78 70 6c 6f 69 74 } //1
		$a_00_2 = {2f 6e 69 67 20 72 65 61 6c 74 65 6b 2e 65 78 70 6c 6f 69 74 } //1 /nig realtek.exploit
		$a_00_3 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 63 68 6d 6f 64 20 37 37 37 20 2a 20 2f 74 6d 70 } //1 /bin/busybox chmod 777 * /tmp
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule Backdoor_Linux_Mirai_F_xp_2{
	meta:
		description = "Backdoor:Linux/Mirai.F!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 07 00 00 "
		
	strings :
		$a_00_0 = {69 6e 69 74 69 61 74 69 6e 67 20 6c 6f 63 6b 64 6f 77 6e } //1 initiating lockdown
		$a_00_1 = {77 6f 72 64 74 68 65 6d 69 6e 65 72 } //1 wordtheminer
		$a_00_2 = {2e 75 70 64 61 74 65 72 } //1 .updater
		$a_00_3 = {53 4f 31 39 30 49 6a 31 58 } //2 SO190Ij1X
		$a_00_4 = {06 30 d2 e7 22 30 23 e2 06 30 c2 e7 01 20 82 e2 02 00 57 e1 f9 ff ff 1a } //1
		$a_00_5 = {77 6f 6c 66 65 78 65 63 62 69 6e } //1 wolfexecbin
		$a_00_6 = {2e 68 62 6f 74 } //1 .hbot
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*2+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=4
 
}