
rule Backdoor_Linux_Gafgyt_BT_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.BT!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {88 50 8f 4a 80 67 08 70 01 2d 40 ff f4 60 04 42 ae ff f4 2d 6e ff f4 ff } //1
		$a_00_1 = {00 0c 20 80 20 6e 00 0c 20 10 72 ff b2 80 66 08 70 01 2d 40 ff f8 60 04 42 ae } //1
		$a_00_2 = {f0 24 6e ff f4 4e 5e 4e 75 4e 56 ff 50 2f 02 22 2e 00 10 20 2e 00 0c 20 40 20 01 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}