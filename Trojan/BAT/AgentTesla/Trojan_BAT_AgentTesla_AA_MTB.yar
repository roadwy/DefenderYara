
rule Trojan_BAT_AgentTesla_AA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {01 25 16 7e 90 01 03 04 a2 25 17 28 90 01 03 06 a2 25 18 72 90 01 03 70 a2 0a 08 20 90 01 04 5a 20 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_AA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 10 00 00 06 0a 06 03 7d 0a 00 00 04 00 02 06 fe 06 11 00 00 06 73 19 00 00 0a 28 06 00 00 2b 28 07 00 00 2b 0b 2b 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_AgentTesla_AA_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0c 07 08 28 15 00 00 0a 2c 28 07 08 17 28 16 00 00 0a 7e 17 00 00 0a 72 1b 00 00 70 6f 18 00 00 0a 08 28 } //2
		$a_01_1 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_AgentTesla_AA_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.AA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 79 73 74 75 6d 2e 53 75 63 75 72 79 74 79 2e 53 72 79 70 } //1 cystum.Sucuryty.Sryp
		$a_01_1 = {46 69 6c 75 53 74 72 75 61 6d } //1 FiluStruam
		$a_01_2 = {50 72 6f 74 75 63 74 51 74 74 72 79 62 75 74 75 } //1 ProtuctQttrybutu
		$a_01_3 = {47 75 6e 65 72 71 74 65 64 53 6f 64 65 51 74 74 72 79 62 75 74 75 } //1 GunerqtedSodeQttrybutu
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_BAT_AgentTesla_AA_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.AA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 57 69 6e 64 6f 77 73 20 55 70 64 61 74 65 20 43 65 72 74 69 66 69 65 72 5c 57 69 6e 64 6f 77 73 20 55 70 64 61 74 65 20 43 65 72 74 69 66 69 65 72 5c 6f 62 6a 5c 44 65 62 75 67 5c 55 70 64 61 74 65 20 43 65 72 74 69 66 69 65 72 2e 70 64 62 } //1 source\repos\Windows Update Certifier\Windows Update Certifier\obj\Debug\Update Certifier.pdb
	condition:
		((#a_01_0  & 1)*1) >=1
 
}