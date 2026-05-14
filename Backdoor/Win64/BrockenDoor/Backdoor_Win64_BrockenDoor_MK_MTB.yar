
rule Backdoor_Win64_BrockenDoor_MK_MTB{
	meta:
		description = "Backdoor:Win64/BrockenDoor.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_03_0 = {4d 8b c8 4c 8b f1 48 89 4d 90 90 45 33 ff 44 89 7c 24 ?? 41 0f b6 44 10 ff 4c 89 79 10 48 c7 41 ?? 0f 00 00 00 44 88 39 44 8b c0 4c 2b c8 48 83 c2 ?? 49 03 d1 e8 } //20
		$a_03_1 = {49 8b cc 49 3b c4 48 0f 42 c8 48 03 ca 80 39 ?? ?? ?? 48 3b ca ?? ?? 48 ff c9 80 39 ?? ?? ?? 48 2b ca ?? ?? 49 8b cc 66 } //15
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*15) >=35
 
}