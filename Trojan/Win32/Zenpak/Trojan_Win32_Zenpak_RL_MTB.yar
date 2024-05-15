
rule Trojan_Win32_Zenpak_RL_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 89 e5 8a 45 0c 8a 4d 08 30 c8 a2 90 01 04 c7 05 90 01 06 00 00 c7 05 90 01 06 00 00 0f b6 c0 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}