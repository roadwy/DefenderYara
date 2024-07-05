
rule Trojan_Win32_Vidar_ASGF_MTB{
	meta:
		description = "Trojan:Win32/Vidar.ASGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {01 02 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 89 45 90 01 01 c7 45 90 01 03 00 00 6a 00 e8 90 01 03 ff 8b 55 90 01 01 81 c2 90 01 03 00 2b 55 90 01 01 2b d0 8b 45 90 01 01 31 10 83 45 ec 04 83 45 d4 04 8b 45 ec 3b 45 d0 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}