
rule HackTool_Linux_Mirai_C_MTB{
	meta:
		description = "HackTool:Linux/Mirai.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 28 2a 42 6f 74 29 2e 48 61 6e 64 6c 65 } //1 main.(*Bot).Handle
		$a_01_1 = {6d 61 69 6e 2e 28 2a 44 61 74 61 62 61 73 65 29 2e 43 61 6e 4c 61 75 6e 63 68 41 74 74 61 63 6b } //1 main.(*Database).CanLaunchAttack
		$a_01_2 = {2a 6d 61 69 6e 2e 41 74 74 61 63 6b 53 65 6e 64 } //1 *main.AttackSend
		$a_01_3 = {6d 61 69 6e 2e 28 2a 42 6f 74 29 2e 51 75 65 75 65 42 75 66 } //1 main.(*Bot).QueueBuf
		$a_01_4 = {6d 61 69 6e 2e 28 2a 44 61 74 61 62 61 73 65 29 2e 43 68 65 63 6b 41 70 69 43 6f 64 65 } //1 main.(*Database).CheckApiCode
		$a_01_5 = {6d 61 69 6e 2e 28 2a 43 6c 69 65 6e 74 4c 69 73 74 29 2e 44 69 73 74 72 69 62 75 74 69 6f 6e } //1 main.(*ClientList).Distribution
		$a_01_6 = {2f 6d 69 72 61 69 2f 63 6e 63 2f 61 74 74 61 63 6b 2e 67 6f } //1 /mirai/cnc/attack.go
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}