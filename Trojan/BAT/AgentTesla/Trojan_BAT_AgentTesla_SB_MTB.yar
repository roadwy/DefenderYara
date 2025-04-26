
rule Trojan_BAT_AgentTesla_SB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {04 06 91 20 ?? ?? ?? ?? 59 d2 9c 00 06 17 58 0a 06 7e ?? ?? ?? ?? 8e 69 fe 04 0b 07 2d d7 } //10
		$a_80_1 = {6e 61 64 6a 6f 64 6f 2e 64 75 63 6b 64 6e 73 2e 6f 72 67 } //nadjodo.duckdns.org  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}
rule Trojan_BAT_AgentTesla_SB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 06 07 02 07 18 5a 18 6f 6c 00 00 0a 1f 10 28 6d 00 00 0a 9c 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d dc } //2
		$a_01_1 = {41 6d 69 67 6f 53 65 63 72 65 74 6f 57 69 6e 46 6f 72 6d 73 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //2 AmigoSecretoWinForms.Form1.resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Trojan_BAT_AgentTesla_SB_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_00_0 = {28 51 00 00 0a 02 d6 6c 0b 2b 0e 17 28 52 00 00 0a 00 28 53 00 00 0a 00 00 28 51 00 00 0a 6c 07 fe 04 0c 08 2d e5 } //10
		$a_80_1 = {43 68 65 63 6b 46 69 6c 65 4c 6f 63 61 74 69 6f 6e } //CheckFileLocation  3
		$a_80_2 = {41 64 64 54 6f 5f 4e 6f 6e 4b 65 79 } //AddTo_NonKey  3
		$a_80_3 = {49 6e 66 6f 5f 47 72 61 62 5f 49 42 } //Info_Grab_IB  3
		$a_80_4 = {57 65 62 5f 4e 65 77 41 64 64 72 65 73 73 } //Web_NewAddress  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}