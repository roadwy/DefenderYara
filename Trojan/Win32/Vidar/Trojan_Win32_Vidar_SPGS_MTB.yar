
rule Trojan_Win32_Vidar_SPGS_MTB{
	meta:
		description = "Trojan:Win32/Vidar.SPGS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 45 b4 f7 d8 33 45 b4 83 e0 01 75 0e 8b 4d b4 81 c1 1e 22 00 00 89 4d b4 eb } //00 00 
	condition:
		any of ($a_*)
 
}