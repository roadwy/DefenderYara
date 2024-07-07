
rule Backdoor_Linux_Bifrose_JJ{
	meta:
		description = "Backdoor:Linux/Bifrose.JJ,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {25 80 00 00 00 85 c0 75 37 8b 45 f0 89 c1 03 4d 08 8b 45 f0 03 45 08 0f b6 10 8b 45 f8 01 c2 b8 ff ff ff ff 21 d0 88 01 8b 45 f0 89 c2 03 55 08 8b 45 f0 03 45 08 0f b6 00 32 45 fd 88 02 } //1
		$a_01_1 = {8b 45 f0 03 45 08 0f b6 00 30 45 fd 8b 45 f0 89 c1 03 4d 08 8b 45 f8 89 c2 02 55 fd b8 ff ff ff ff 21 d0 88 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}