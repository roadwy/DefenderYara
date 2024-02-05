
rule Trojan_Win32_Vidar_RL_MTB{
	meta:
		description = "Trojan:Win32/Vidar.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {51 c7 04 24 04 00 00 00 8b 44 24 08 83 2c 24 04 90 01 04 24 8b 04 24 31 01 59 c2 04 00 } //00 00 
	condition:
		any of ($a_*)
 
}