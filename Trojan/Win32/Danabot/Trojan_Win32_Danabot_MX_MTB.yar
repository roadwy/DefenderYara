
rule Trojan_Win32_Danabot_MX_MTB{
	meta:
		description = "Trojan:Win32/Danabot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 ca c1 e8 05 03 c5 89 4c 24 90 01 01 89 44 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 2b 7c 24 90 01 01 81 3d 90 01 04 bb 06 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Danabot_MX_MTB_2{
	meta:
		description = "Trojan:Win32/Danabot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {f7 a4 24 e0 00 00 00 8b 84 24 e0 00 00 00 81 84 24 90 01 04 f3 ae ac 68 81 ac 24 90 01 04 b3 30 c7 6b 81 84 24 90 01 04 21 f4 7c 36 30 0c 1e 4e 0f 89 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}