
rule Backdoor_Linux_BPFDoor_G_MTB{
	meta:
		description = "Backdoor:Linux/BPFDoor.G!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 45 ff 83 c0 01 88 45 ff 0f b6 55 ff 48 8b 45 f0 48 01 d0 0f b6 00 00 45 fe 0f b6 55 fe 48 8b 45 f0 48 01 c2 0f b6 4d ff 48 8b 45 f0 48 01 c8 48 89 d6 48 89 c7 e8 7c fe ff ff } //1
		$a_01_1 = {48 8b 45 f0 48 01 d0 0f b6 10 0f b6 4d fe 48 8b 45 f0 48 01 c8 0f b6 00 01 d0 88 45 ef 8b 45 f8 48 63 d0 48 8b 45 d8 48 01 c2 8b 45 f8 48 63 c8 48 8b 45 d8 48 01 c8 0f b6 08 0f b6 75 ef 48 8b 45 f0 48 01 f0 0f b6 00 31 c8 88 02 83 45 f8 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}