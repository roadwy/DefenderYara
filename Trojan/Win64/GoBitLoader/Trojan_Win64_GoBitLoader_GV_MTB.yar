
rule Trojan_Win64_GoBitLoader_GV_MTB{
	meta:
		description = "Trojan:Win64/GoBitLoader.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 52 65 64 69 72 65 63 74 54 6f 50 61 79 6c 6f 61 64 } //3 main.RedirectToPayload
		$a_01_1 = {6d 61 69 6e 2e 48 6f 6c 6c 6f 77 50 72 6f 63 65 73 73 } //3 main.HollowProcess
		$a_01_2 = {6d 61 69 6e 2e 41 65 73 44 65 63 6f 64 65 2e 66 75 6e 63 31 } //3 main.AesDecode.func1
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3) >=9
 
}