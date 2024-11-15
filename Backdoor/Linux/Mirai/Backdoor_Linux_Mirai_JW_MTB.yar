
rule Backdoor_Linux_Mirai_JW_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.JW!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c2 14 80 00 82 15 00 01 82 18 61 40 80 88 63 40 12 ?? ?? ?? ?? 10 00 13 7f ff ff 01 ?? 10 00 12 80 a2 20 00 22 ?? ?? ?? c2 14 80 00 10 ?? ?? ?? a2 10 3f ff } //1
		$a_03_1 = {23 00 01 00 84 04 a0 01 82 14 60 03 82 0c 00 01 82 00 60 01 84 08 40 02 80 a0 80 01 12 ?? ?? ?? f6 26 20 04 82 2c 00 12 80 88 60 08 02 ?? ?? ?? 82 0c 80 11 ?? 10 00 1b 92 10 20 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}