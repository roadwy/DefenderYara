
rule Trojan_Linux_Mirai_SK_AMTB{
	meta:
		description = "Trojan:Linux/Mirai.SK!AMTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {65 63 66 61 66 65 61 62 36 65 65 37 64 36 34 32 } //ecfafeab6ee7d642  1
		$a_80_1 = {25 73 2f 25 73 2f 25 73 2e 73 68 } //%s/%s/%s.sh  1
		$a_80_2 = {2a 2a 2a 20 25 73 20 2a 2a 2a 3a 20 74 65 72 6d 69 6e 61 74 65 64 } //*** %s ***: terminated  1
		$a_80_3 = {6c 6f 63 6b 5f 66 69 6c 65 } //lock_file  1
		$a_80_4 = {2f 70 72 6f 63 2f 63 70 75 69 6e 66 6f } ///proc/cpuinfo  1
		$a_80_5 = {64 65 6c 65 74 65 5b 5d } //delete[]  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}