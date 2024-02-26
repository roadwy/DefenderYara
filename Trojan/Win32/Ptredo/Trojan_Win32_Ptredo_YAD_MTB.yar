
rule Trojan_Win32_Ptredo_YAD_MTB{
	meta:
		description = "Trojan:Win32/Ptredo.YAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 89 75 40 85 f6 74 33 c7 45 fc 06 00 00 00 } //01 00 
		$a_01_1 = {8b 7d 48 8a 44 1e ff 84 c0 74 ca 30 04 1e eb c5 } //00 00 
	condition:
		any of ($a_*)
 
}