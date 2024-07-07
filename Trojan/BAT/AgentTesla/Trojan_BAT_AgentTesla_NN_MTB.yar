
rule Trojan_BAT_AgentTesla_NN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d 13 0b 07 11 0b 91 11 08 58 13 0c 07 11 0a 91 13 0d 08 11 07 1f 16 5d 91 13 0e 90 01 04 61 13 0f 07 11 0a 90 01 04 59 11 08 5d d2 9c 00 11 07 17 58 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_BAT_AgentTesla_NN_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {57 69 6e 43 6c 69 65 6e 74 2e 66 72 6d 6c 6f 67 69 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 WinClient.frmlogin.resources
		$a_81_1 = {45 6d 70 6c 79 65 65 20 41 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 20 50 72 6f 67 72 61 6d } //1 Emplyee Authentication Program
		$a_81_2 = {24 65 34 34 65 64 37 64 61 2d 66 35 31 32 2d 34 37 66 63 2d 61 31 61 38 2d 35 61 62 31 37 61 38 63 36 33 37 35 } //1 $e44ed7da-f512-47fc-a1a8-5ab17a8c6375
		$a_81_3 = {4e 65 74 77 6f 72 6b 5f 50 72 69 6e 74 65 72 2e 74 78 74 } //1 Network_Printer.txt
		$a_81_4 = {47 6c 6f 62 61 6c 5f 44 65 63 6c 61 72 61 74 69 6f 6e 73 } //1 Global_Declarations
		$a_81_5 = {62 74 6e 65 6d 70 6d 6e 67 6d 6e 74 } //1 btnempmngmnt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}