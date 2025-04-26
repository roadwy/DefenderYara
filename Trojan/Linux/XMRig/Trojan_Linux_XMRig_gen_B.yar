
rule Trojan_Linux_XMRig_gen_B{
	meta:
		description = "Trojan:Linux/XMRig.gen!B!!XMRig.gen!B,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_81_0 = {22 64 6f 6e 61 74 65 2d 6c 65 76 65 6c 22 3a } //1 "donate-level":
		$a_81_1 = {22 64 6f 6e 61 74 65 2d 6f 76 65 72 2d 70 72 6f 78 79 22 3a } //1 "donate-over-proxy":
		$a_81_2 = {22 6e 69 63 65 68 61 73 68 22 3a } //1 "nicehash":
		$a_81_3 = {22 73 63 72 61 74 63 68 70 61 64 5f 70 72 65 66 65 74 63 68 5f 6d 6f 64 65 22 3a } //1 "scratchpad_prefetch_mode":
		$a_81_4 = {22 61 73 74 72 6f 62 77 74 2d 6d 61 78 2d 73 69 7a 65 22 3a } //1 "astrobwt-max-size":
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=3
 
}