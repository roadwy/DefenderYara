
rule Trojan_Win32_Vidar_SPGG_MTB{
	meta:
		description = "Trojan:Win32/Vidar.SPGG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 c4 04 8b 44 24 0c 83 c0 64 89 44 24 08 83 6c 24 08 64 8a 4c 24 08 30 0c 3e 46 3b f3 7c } //00 00 
	condition:
		any of ($a_*)
 
}