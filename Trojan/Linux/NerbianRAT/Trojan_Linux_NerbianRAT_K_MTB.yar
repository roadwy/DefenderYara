
rule Trojan_Linux_NerbianRAT_K_MTB{
	meta:
		description = "Trojan:Linux/NerbianRAT.K!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {73 79 73 74 65 6d 5f 63 6d 64 } //2 system_cmd
		$a_00_1 = {74 69 6d 65 5f 66 6c 61 67 5f 63 68 61 6e 67 65 } //2 time_flag_change
		$a_00_2 = {63 6f 72 65 5f 63 6f 6e 66 69 67 5f 73 65 74 } //2 core_config_set
		$a_00_3 = {48 c7 45 f0 00 00 00 00 ba b6 03 00 00 be 04 00 00 00 bf 07 27 00 00 e8 6f a1 23 00 89 45 ec 83 7d ec ff } //1
		$a_00_4 = {8b 45 ec ba 00 00 00 00 be 00 00 00 00 89 c7 e8 08 a1 23 00 48 89 45 f0 48 83 7d f0 ff } //1
		$a_00_5 = {48 8b 45 f0 48 89 45 f8 48 8b 45 f8 8b 00 85 c0 74 18 48 8b 45 f8 8b 00 89 c7 e8 54 5d 23 00 85 c0 } //2
		$a_00_6 = {48 8b 45 f0 48 89 c7 e8 be a0 23 00 83 f8 ff 0f 94 c0 84 c0 } //2
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*2+(#a_00_6  & 1)*2) >=6
 
}