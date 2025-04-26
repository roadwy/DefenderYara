
rule Trojan_Win64_Convagent_AD_MTB{
	meta:
		description = "Trojan:Win64/Convagent.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 06 00 00 "
		
	strings :
		$a_00_0 = {48 89 5c 24 08 48 89 74 24 10 48 89 7c 24 18 4c 89 64 24 20 55 41 56 41 57 48 8d ac 24 d0 fe ff ff 48 81 ec 30 02 00 00 48 8b 05 51 5f 00 00 48 33 c4 48 89 85 20 01 00 00 bf 46 9c 00 00 c7 85 f0 00 00 00 18 00 21 00 8b df c7 85 f4 00 00 00 70 00 0d 00 c7 85 f8 00 00 00 bb 00 ab 00 c7 44 24 30 b3 } //10
		$a_80_1 = {4f 70 65 6e 44 6f 64 67 65 6d } //OpenDodgem  3
		$a_80_2 = {4e 6f 74 69 66 79 42 75 6c 6c 6f 63 6b 36 34 } //NotifyBullock64  3
		$a_80_3 = {47 65 74 54 68 72 65 61 64 50 72 69 6f 72 69 74 79 42 6f 6f 73 74 } //GetThreadPriorityBoost  3
		$a_80_4 = {57 6f 72 6b 49 6e 68 61 6c 61 74 6f 72 } //WorkInhalator  3
		$a_80_5 = {41 79 65 72 } //Ayer  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3) >=25
 
}