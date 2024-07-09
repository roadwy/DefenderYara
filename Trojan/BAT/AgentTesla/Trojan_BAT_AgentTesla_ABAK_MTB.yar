
rule Trojan_BAT_AgentTesla_ABAK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 08 18 5b 02 08 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 08 18 58 0c 08 06 32 e4 07 2a } //3
		$a_01_1 = {45 00 70 00 76 00 66 00 74 00 63 00 75 00 6d 00 73 00 6d 00 62 00 72 00 74 00 2e 00 51 00 62 00 6c 00 6c 00 79 00 79 00 69 00 6f 00 6e 00 70 00 6c 00 64 00 69 00 } //1 Epvftcumsmbrt.Qbllyyionpldi
		$a_01_2 = {47 00 6d 00 76 00 68 00 78 00 76 00 7a 00 6e 00 62 00 61 00 6d 00 61 00 } //1 Gmvhxvznbama
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}