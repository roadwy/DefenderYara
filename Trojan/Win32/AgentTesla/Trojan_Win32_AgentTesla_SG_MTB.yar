
rule Trojan_Win32_AgentTesla_SG_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {b9 50 f3 07 41 90 02 06 81 c1 f1 4d 39 00 90 02 06 83 c6 03 90 02 06 4e 90 02 02 4e 90 02 04 ff 37 90 02 04 31 34 24 90 02 04 5b 90 02 04 39 cb 75 90 00 } //01 00 
		$a_02_1 = {bb 20 00 01 00 90 02 0a 83 eb 03 a9 6b eb 50 3f 83 eb 01 90 02 06 ff 34 1f 90 02 0a f7 c6 bf 3d 51 3f 90 02 06 8f 04 18 90 02 10 31 34 18 90 02 2a 81 f9 90 01 04 90 02 06 7f 90 00 } //00 00 
		$a_00_2 = {7e } //15 00 
	condition:
		any of ($a_*)
 
}