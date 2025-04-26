
rule Trojan_BAT_Remcos_RVE_MTB{
	meta:
		description = "Trojan:BAT/Remcos.RVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {57 95 a2 29 09 0f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 77 00 00 00 14 00 00 00 65 00 00 00 77 00 00 00 65 00 00 00 0f 01 00 00 6c 00 00 00 01 00 00 00 24 00 00 00 08 00 00 00 1c 00 00 00 2a 00 00 00 26 00 00 00 01 00 00 00 01 00 00 00 07 00 00 00 03 00 00 00 06 00 00 00 0a 00 00 00 12 } //1
		$a_81_1 = {54 6f 44 6f 4c 69 73 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 ToDoList.Properties.Resources.resources
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}