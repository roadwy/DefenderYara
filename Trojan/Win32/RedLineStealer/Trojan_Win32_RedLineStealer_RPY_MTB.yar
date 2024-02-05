
rule Trojan_Win32_RedLineStealer_RPY_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.RPY!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c7 c1 e0 04 03 45 e8 03 cf 33 c1 89 45 fc 8d 45 fc 50 e8 } //01 00 
		$a_01_1 = {8b 45 08 89 78 04 5f 89 30 5e 5b } //00 00 
	condition:
		any of ($a_*)
 
}