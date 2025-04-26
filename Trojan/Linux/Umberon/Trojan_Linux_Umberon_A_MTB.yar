
rule Trojan_Linux_Umberon_A_MTB{
	meta:
		description = "Trojan:Linux/Umberon.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 08 00 00 "
		
	strings :
		$a_00_0 = {67 65 74 5f 68 69 64 65 70 6f 72 74 73 } //1 get_hideports
		$a_00_1 = {67 65 74 5f 6d 79 5f 70 72 6f 63 6e 61 6d 65 } //1 get_my_procname
		$a_00_2 = {72 65 69 6e 73 74 61 6c 6c 5f 73 65 6c 66 } //1 reinstall_self
		$a_02_3 = {75 73 72 2f 73 68 61 72 65 2f 6c 69 62 63 2e 73 6f 2e [0-15] 2e 24 7b 50 4c 41 54 46 4f 52 4d 7d 2e 6c 64 2d 32 2e 32 32 2e 73 6f } //2
		$a_00_4 = {2f 65 74 63 2f 6c 64 2e 73 6f 2e 4e 31 4a 66 54 76 69 } //2 /etc/ld.so.N1JfTvi
		$a_00_5 = {48 8b 45 e8 8b 40 08 89 c7 e8 a6 fd ff ff 89 45 e0 48 8b 45 e8 8b 40 04 89 c7 e8 95 fd ff ff 89 45 dc 48 8b 45 f8 0f b7 40 04 0f b7 c0 89 c7 e8 20 fd ff ff 66 89 45 da 81 7d e0 00 c5 00 00 75 2b 81 7d dc c4 00 00 00 75 22 66 81 7d da b1 0f 75 1a 48 8b 45 e8 0f b7 00 0f b7 d0 48 8b 45 f8 8b 40 0c 89 d6 89 c7 e8 97 fe ff ff } //1
		$a_02_6 = {2f 6c 69 62 63 2e 73 6f 2e [0-15] 2f 62 69 6e 2f 65 73 70 65 6f 6e 2d 73 68 65 6c 6c } //2
		$a_00_7 = {62 61 63 6b 63 6f 6e 6e 65 63 74 } //2 backconnect
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*1+(#a_02_6  & 1)*2+(#a_00_7  & 1)*2) >=4
 
}