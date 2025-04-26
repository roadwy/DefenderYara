
rule Trojan_BAT_AgentTesla_ABPL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 72 61 76 69 61 6e 47 61 6d 65 5f 57 69 6e 64 6f 77 73 46 6f 72 6d 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 TravianGame_WindowsForms.Properties.Resources.resources
		$a_01_1 = {57 69 6e 64 6f 77 73 49 6e 74 65 72 66 61 63 65 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //2 WindowsInterface.Form1.resources
		$a_01_2 = {54 00 72 00 61 00 76 00 69 00 61 00 6e 00 47 00 61 00 6d 00 65 00 5f 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 } //1 TravianGame_WindowsForms
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}