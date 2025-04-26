
rule Trojan_BAT_AgentTesla_ABNF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABNF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 61 6d 65 73 54 65 73 74 2e 52 65 73 6f 75 72 63 65 49 6e 76 65 6e 74 6f 72 79 2e 72 65 73 6f 75 72 63 65 73 } //2 GamesTest.ResourceInventory.resources
		$a_01_1 = {67 65 74 5f 44 41 53 4a 48 44 42 4a 4b 41 44 48 42 4b 4a 44 } //2 get_DASJHDBJKADHBKJD
		$a_01_2 = {67 65 74 5f 48 4a 53 41 42 4a 44 47 4a 53 41 48 44 47 41 53 4a 48 44 47 41 4a 48 53 47 44 } //2 get_HJSABJDGJSAHDGASJHDGAJHSGD
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}