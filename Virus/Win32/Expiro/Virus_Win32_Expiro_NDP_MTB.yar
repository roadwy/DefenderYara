
rule Virus_Win32_Expiro_NDP_MTB{
	meta:
		description = "Virus:Win32/Expiro.NDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {57 e8 00 00 00 00 90 01 01 81 90 01 01 0c 90 01 01 08 00 90 01 01 00 00 00 00 90 00 } //01 00 
		$a_03_1 = {00 04 00 00 81 90 01 01 00 04 00 00 81 90 01 01 00 c0 08 00 90 00 } //01 00 
		$a_03_2 = {2e 72 65 6c 6f 63 00 00 00 90 02 15 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}