
rule Backdoor_Linux_Mirai_KB_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.KB!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {7f ab fa 14 3b 9d 00 01 7f 9c c0 40 40 ?? ?? ?? 7c 9a f2 14 7c 79 5a 14 7f e5 fb 78 4b ff 9b 79 7c 9e fa 14 41 ?? ?? ?? 7f 7b fa 14 7c 1a 20 ae 2f 80 00 00 41 ?? ?? ?? 38 00 00 2e 7c 19 e9 ae 7f 8b e3 78 } //1
		$a_03_1 = {2f 80 00 00 7d 3c d8 50 39 7c 00 01 39 29 ff ff 7f e4 fb 78 7c 7d 5a 14 7c 05 03 78 7f 00 48 40 3b fe 00 01 41 ?? ?? ?? 40 ?? ?? ?? 7c 1d e1 ae 7f 8b 02 14 4b ff 9c 5d 2f 9e 00 00 41 ?? ?? ?? 2f 9f 00 00 38 80 00 2e 7f e3 fb 78 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}