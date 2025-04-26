
rule Trojan_Win32_FrostyGoop_A_MTB{
	meta:
		description = "Trojan:Win32/FrostyGoop.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {72 6f 6c 66 6c 2f 6d 6f 64 62 75 73 } //1 rolfl/modbus
		$a_81_1 = {6d 61 69 6e 2e 54 61 73 6b 4c 69 73 74 2e 65 78 65 63 75 74 65 43 6f 6d 6d 61 6e 64 } //1 main.TaskList.executeCommand
		$a_81_2 = {6d 61 69 6e 2e 54 61 72 67 65 74 4c 69 73 74 2e 67 65 74 54 61 72 67 65 74 49 70 4c 69 73 74 } //1 main.TargetList.getTargetIpList
		$a_81_3 = {6d 61 69 6e 2e 54 61 73 6b 4c 69 73 74 2e 67 65 74 54 61 73 6b 49 70 4c 69 73 74 } //1 main.TaskList.getTaskIpList
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}