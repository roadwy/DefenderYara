
rule Trojan_Win32_Agent_AAE{
	meta:
		description = "Trojan:Win32/Agent.AAE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 75 08 8b 46 3c 8b 44 30 78 03 c6 8b 90 01 01 1c 8b 90 01 01 20 8b 90 01 01 24 8b 90 01 01 18 90 00 } //01 00 
		$a_01_1 = {29 45 08 8b 45 08 c1 c8 07 89 45 08 ff 45 } //01 00 
		$a_02_2 = {0f 84 07 00 00 00 0f 85 01 00 00 00 e8 0f b6 85 90 01 02 ff ff 83 e0 0f 90 00 } //01 00 
		$a_03_3 = {83 f8 72 75 90 01 01 0f be 85 90 01 02 ff ff 83 f8 03 75 2a 0f be 85 90 01 02 ff ff 83 f8 73 75 1e 0f be 85 83 ea ff ff 83 f8 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}