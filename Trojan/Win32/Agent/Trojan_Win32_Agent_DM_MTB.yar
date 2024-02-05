
rule Trojan_Win32_Agent_DM_MTB{
	meta:
		description = "Trojan:Win32/Agent.DM!MTB,SIGNATURE_TYPE_PEHSTR,02 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 0a c0 e5 f3 66 0f ab d1 80 f1 cb 8b 4c 25 00 f8 81 c5 04 00 00 00 f9 33 cb } //01 00 
		$a_01_1 = {01 6a 3d 2a bc f9 95 17 3c ed a5 95 30 9b 2a 1b 6a 31 } //00 00 
	condition:
		any of ($a_*)
 
}