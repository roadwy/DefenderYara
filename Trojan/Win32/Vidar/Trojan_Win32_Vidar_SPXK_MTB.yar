
rule Trojan_Win32_Vidar_SPXK_MTB{
	meta:
		description = "Trojan:Win32/Vidar.SPXK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 44 24 18 33 4c 24 14 03 44 24 2c 33 c1 c7 05 } //00 00 
	condition:
		any of ($a_*)
 
}