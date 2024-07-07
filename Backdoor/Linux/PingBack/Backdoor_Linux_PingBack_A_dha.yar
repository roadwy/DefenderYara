
rule Backdoor_Linux_PingBack_A_dha{
	meta:
		description = "Backdoor:Linux/PingBack.A!dha,SIGNATURE_TYPE_ELFHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {ba 01 00 00 00 be 03 00 00 00 bf 02 00 00 00 e8 90 01 04 89 45 d4 83 7d d4 ff 90 00 } //5
		$a_01_1 = {69 6e 70 75 74 20 70 72 6f 70 65 72 20 62 69 6e 64 20 69 70 20 61 64 64 72 } //1 input proper bind ip addr
		$a_01_2 = {63 61 6e 27 74 20 62 69 6e 64 20 74 6f 20 61 64 64 72 } //1 can't bind to addr
		$a_01_3 = {5b 77 61 74 63 68 64 6f 67 2f 31 5d } //1 [watchdog/1]
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}