
rule Trojan_Win32_Qakbot_SAC_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 54 24 34 83 c2 90 01 01 8b 4c 24 90 01 01 8b 81 90 01 04 0f af 81 90 01 04 8b 7c 24 90 01 01 31 f8 39 c2 8b 6c 24 90 00 } //01 00 
		$a_01_1 = {d1 5a 41 00 59 d1 8b 00 95 33 cd 00 44 b5 72 00 } //01 00 
		$a_01_2 = {be 53 47 00 ba 57 53 00 ff 96 46 00 09 be 80 00 } //00 00 
	condition:
		any of ($a_*)
 
}