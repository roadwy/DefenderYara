
rule Trojan_Win32_AgentTesla_RS_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {50 58 50 58 90 02 05 51 59 90 02 05 90 90 90 05 10 01 90 90 02 05 90 90 90 05 10 01 90 51 59 90 90 90 05 10 01 90 81 34 08 bf 15 cf e4 90 02 06 50 58 90 00 } //01 00 
		$a_00_1 = {50 58 51 59 ff e0 } //01 00 
		$a_00_2 = {c3 8b 0c 24 83 c1 01 c3 } //00 00 
	condition:
		any of ($a_*)
 
}