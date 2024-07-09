
rule Trojan_Win32_AgentTesla_RS_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {50 58 50 58 [0-05] 51 59 [0-05] 90 90 90 05 10 01 90 [0-05] 90 90 90 05 10 01 90 51 59 90 90 90 05 10 01 90 81 34 08 bf 15 cf e4 [0-06] 50 58 } //1
		$a_00_1 = {50 58 51 59 ff e0 } //1
		$a_00_2 = {c3 8b 0c 24 83 c1 01 c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}