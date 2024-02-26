
rule Backdoor_Win32_Hupigon_DW_MTB{
	meta:
		description = "Backdoor:Win32/Hupigon.DW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 c2 01 da 8b 12 81 e2 90 01 04 8b 59 90 01 01 01 c3 c1 e2 90 01 01 01 d3 8b 13 90 00 } //01 00 
		$a_03_1 = {8a 18 80 c3 90 01 01 80 f3 90 01 01 80 c3 90 01 01 88 18 40 49 83 f9 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}