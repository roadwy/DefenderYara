
rule Backdoor_Linux_Blackhole_B_xp{
	meta:
		description = "Backdoor:Linux/Blackhole.B!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {c7 45 f4 60 89 04 08 c7 45 f0 80 89 04 08 c7 45 ec c0 89 04 08 66 c7 45 c8 02 00 83 ec 0c 68 39 30 00 00 e8 e8 fe ff ff 83 c4 10 66 89 45 ca c7 45 cc 00 00 00 00 } //1
		$a_00_1 = {49 5f 64 69 64 5f 6e 6f 74 5f 63 68 61 6e 67 65 5f 48 49 44 45 } //1 I_did_not_change_HIDE
		$a_00_2 = {53 6f 63 6b 65 74 20 65 72 72 6f 72 0a 00 42 69 6e 64 20 65 72 72 6f 72 0a 00 4c 69 73 74 65 6e 20 65 72 72 6f 72 0a 00 41 63 63 65 70 74 20 65 72 72 6f 72 00 2f 62 69 6e 2f 73 68 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}