
rule Backdoor_Linux_Gafgyt_CV_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.CV!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {8b 45 b4 83 f8 03 76 4c e8 b7 fe ff ff 89 45 f8 c7 45 f4 00 00 00 00 eb 28 } //1
		$a_00_1 = {8b 45 f8 88 45 ff c1 6d f8 08 c0 6d ff 03 0f b6 45 ff 48 98 } //1
		$a_00_2 = {48 98 0f b6 44 05 d0 89 c2 48 8b 45 c8 88 10 48 ff 45 c8 ff 45 f4 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}