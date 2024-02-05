
rule Trojan_Win32_Qakbot_CT_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.CT!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 ec 28 64 a1 30 00 00 00 3a e4 74 16 } //01 00 
		$a_01_1 = {89 45 e0 8b 45 e0 3a f6 74 bf } //01 00 
		$a_01_2 = {8b 40 0c 8b 40 0c 66 3b e4 74 00 } //01 00 
		$a_01_3 = {8b 00 8b 00 66 3b c9 74 0d } //00 00 
	condition:
		any of ($a_*)
 
}