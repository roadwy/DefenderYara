
rule Trojan_Win32_Dejandet_I_MTB{
	meta:
		description = "Trojan:Win32/Dejandet.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 01 08 83 c0 02 66 83 38 00 75 ef 90 0a 40 00 c7 45 90 01 05 c7 45 90 01 05 c7 45 90 01 05 c7 45 90 01 05 90 02 10 b9 90 01 01 00 00 00 66 01 08 83 c0 02 66 83 38 00 75 ef 90 00 } //01 00 
		$a_03_1 = {66 01 08 83 c0 02 66 83 38 00 75 ef 90 0a 40 00 c7 85 90 01 08 c7 85 90 01 08 c7 85 90 01 08 c7 85 90 01 08 90 02 10 b9 90 01 01 00 00 00 66 01 08 83 c0 02 66 83 38 00 75 ef 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}