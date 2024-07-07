
rule Backdoor_Linux_Mirai_L_xp{
	meta:
		description = "Backdoor:Linux/Mirai.L!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 41 53 55 4e 41 } //1 /bin/busybox ASUNA
		$a_00_1 = {68 61 63 6b 74 68 65 77 6f 72 6c 64 31 33 33 37 } //1 hacktheworld1337
		$a_00_2 = {74 30 74 61 6c 63 30 6e 74 72 30 6c 34 } //1 t0talc0ntr0l4
		$a_00_3 = {76 73 74 61 72 63 61 6d 32 30 31 35 } //1 vstarcam2015
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}