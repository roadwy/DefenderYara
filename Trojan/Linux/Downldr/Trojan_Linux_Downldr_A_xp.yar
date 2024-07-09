
rule Trojan_Linux_Downldr_A_xp{
	meta:
		description = "Trojan:Linux/Downldr.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {78 6d 72 69 67 } //1 xmrig
		$a_02_1 = {65 63 68 6f 20 27 2a 20 2a 20 2a 20 2a 20 2a 20 65 63 68 6f 20 2d 6e [0-05] 7c 20 62 61 73 65 36 34 20 2d 64 20 7c 73 68 20 3e 20 2f 64 65 76 2f 6e 75 6c 6c 20 32 3e 26 31 27 20 7c 20 63 72 6f 6e 74 61 62 } //1
		$a_00_2 = {69 6e 69 74 72 64 2e 74 61 72 67 65 74 } //1 initrd.target
		$a_00_3 = {6e 65 74 77 6f 72 6b 2e 74 61 72 67 65 74 } //1 network.target
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}