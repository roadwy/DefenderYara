
rule Trojan_Win32_Vidar_AC_MTB{
	meta:
		description = "Trojan:Win32/Vidar.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 44 24 14 33 f5 33 c6 2b f8 81 c3 47 86 c8 61 ff 4c 24 24 89 44 24 14 } //01 00 
		$a_01_1 = {8b 74 24 20 8b 4c 24 18 89 3e 89 4e 04 83 3d 20 61 7b 00 17 } //00 00 
	condition:
		any of ($a_*)
 
}