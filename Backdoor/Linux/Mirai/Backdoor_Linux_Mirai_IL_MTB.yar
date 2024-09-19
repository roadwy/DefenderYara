
rule Backdoor_Linux_Mirai_IL_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.IL!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3c 60 18 82 00 bf d0 82 08 60 ff 80 a0 60 09 08 ?? ?? ?? a2 04 3f d0 82 00 bf bf 82 08 60 ff 80 a0 60 19 08 ?? ?? ?? 82 10 20 37 82 00 bf 9f 82 08 60 ff 80 a0 60 19 18 ?? ?? ?? 80 a0 e0 00 82 10 20 57 } //1
		$a_03_1 = {82 06 7f f4 f6 27 a0 50 80 a0 60 02 f8 27 a0 54 82 07 a0 50 fa 27 a0 58 f4 27 a0 4c ?? 10 00 18 92 10 00 19 94 10 00 1a 18 ?? ?? ?? c2 27 bf f4 40 00 00 15 01 00 00 00 81 c7 e0 08 91 e8 00 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}