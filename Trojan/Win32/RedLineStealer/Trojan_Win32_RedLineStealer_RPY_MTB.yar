
rule Trojan_Win32_RedLineStealer_RPY_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {f6 17 33 f3 33 c0 33 db 33 c6 8b f3 33 c6 8b f3 8b f0 8b d8 80 07 75 33 f0 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_RedLineStealer_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/RedLineStealer.RPY!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c7 c1 e0 04 03 45 e8 03 cf 33 c1 89 45 fc 8d 45 fc 50 e8 } //01 00 
		$a_01_1 = {8b 45 08 89 78 04 5f 89 30 5e 5b } //00 00 
	condition:
		any of ($a_*)
 
}