
rule Backdoor_Linux_Gafgyt_CS_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.CS!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {e2 f0 45 bd e8 1e ff 2f e1 d0 0f 01 00 } //1
		$a_00_1 = {3c bf 73 7f dd 4f 15 75 25 78 00 } //1
		$a_00_2 = {7f b0 b0 b0 80 74 ce ff 7f b0 b0 b0 80 74 ce } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}