
rule Trojan_Win64_MalDrv_D_MTB{
	meta:
		description = "Trojan:Win64/MalDrv.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_81_0 = {57 68 61 74 41 6d 49 44 6f 69 6e 67 48 65 72 65 } //1 WhatAmIDoingHere
		$a_81_1 = {5c 44 6f 73 44 65 76 69 63 65 73 5c 49 6c 6c 75 73 69 6f 6e 69 7a 65 49 73 47 6f 6f 64 41 73 46 75 63 6b } //1 \DosDevices\IllusionizeIsGoodAsFuck
		$a_81_2 = {62 61 74 65 72 79 4c 69 66 65 41 6c 6c 34 } //1 bateryLifeAll4
		$a_81_3 = {5c 44 6f 73 44 65 76 69 63 65 73 5c 79 65 73 53 69 6c 65 6e 74 56 69 65 77 } //1 \DosDevices\yesSilentView
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=2
 
}