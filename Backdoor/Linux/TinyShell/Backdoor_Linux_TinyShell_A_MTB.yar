
rule Backdoor_Linux_TinyShell_A_MTB{
	meta:
		description = "Backdoor:Linux/TinyShell.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 8b 4d 08 01 c1 8b 45 f8 8b 55 08 01 c2 8a 45 ff 32 02 88 01 8d 45 f8 ff 00 } //2
		$a_01_1 = {69 63 6d 70 5b 34 3a 32 5d 20 3d 3d 20 30 78 61 61 35 36 } //1 icmp[4:2] == 0xaa56
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}