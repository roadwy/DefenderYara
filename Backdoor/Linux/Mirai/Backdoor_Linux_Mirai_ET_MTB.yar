
rule Backdoor_Linux_Mirai_ET_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.ET!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {88 1d 00 04 81 3d 00 00 3b bd 00 05 98 0b 00 14 91 2b 00 04 91 2b 00 10 b1 4b 00 00 39 6b 00 18 42 ?? ?? ?? 1d 3a ff fb 7d 3e 4a 14 3b 89 ff fa } //1
		$a_03_1 = {34 1c ff ff 7c 09 03 a6 41 ?? ?? ?? 88 1d 00 01 39 3d 00 01 98 03 00 04 42 ?? ?? ?? 7d 69 02 a6 8b e9 00 01 38 89 00 01 3b ab ff ff 7f 9d f8 00 41 9c 00 a8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}