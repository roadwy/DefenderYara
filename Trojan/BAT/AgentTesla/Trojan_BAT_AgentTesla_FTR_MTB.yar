
rule Trojan_BAT_AgentTesla_FTR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FTR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_00_0 = {02 50 06 03 06 02 50 8e 69 59 03 8e 69 58 91 9c 06 17 58 0a 06 02 50 8e 69 32 e5 } //10
		$a_80_1 = {52 65 73 6f 75 72 63 65 4d 61 6e 61 67 65 72 } //ResourceManager  3
		$a_80_2 = {43 61 6c 6c 42 79 4e 61 6d 65 } //CallByName  3
		$a_80_3 = {67 65 74 5f 45 6e 74 72 79 50 6f 69 6e 74 } //get_EntryPoint  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3) >=19
 
}