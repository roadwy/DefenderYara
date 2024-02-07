
rule Trojan_BAT_AgentTesla_NYB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NYB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 15 a2 1d 09 01 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 81 00 00 00 17 00 00 00 dd 01 00 00 1d 01 00 00 6f 01 00 00 f3 } //01 00 
		$a_01_1 = {51 75 61 6e 4c 79 4e 68 61 44 61 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //00 00  QuanLyNhaDat.Properties.Resources.resource
	condition:
		any of ($a_*)
 
}