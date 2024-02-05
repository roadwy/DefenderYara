
rule Trojan_Win32_Recordbreaker_RPY_MTB{
	meta:
		description = "Trojan:Win32/Recordbreaker.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 11 c1 ea 02 c1 e6 06 8d b4 32 01 07 00 00 8b f8 2b fe 8a 17 88 10 8a 57 01 88 50 01 8a 57 02 41 88 50 02 83 c0 03 8b de 0f b6 79 ff 83 e7 03 } //00 00 
	condition:
		any of ($a_*)
 
}