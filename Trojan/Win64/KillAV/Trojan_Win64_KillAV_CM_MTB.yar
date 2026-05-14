
rule Trojan_Win64_KillAV_CM_MTB{
	meta:
		description = "Trojan:Win64/KillAV.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {45 44 52 4b 69 6c 6c 65 72 } //2 EDRKiller
		$a_01_1 = {6d 61 69 6e 2e 28 2a 42 59 4f 56 44 29 2e 4b 69 6c 6c 50 72 6f 63 65 73 73 } //2 main.(*BYOVD).KillProcess
		$a_01_2 = {6d 61 69 6e 2e 47 65 74 50 49 44 42 79 4e 61 6d 65 } //2 main.GetPIDByName
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}