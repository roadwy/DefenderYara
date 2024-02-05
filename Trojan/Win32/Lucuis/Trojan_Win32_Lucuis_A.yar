
rule Trojan_Win32_Lucuis_A{
	meta:
		description = "Trojan:Win32/Lucuis.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 55 4c 5f 46 49 4c 45 5f 4f 4b 00 } //01 00 
		$a_01_1 = {4c 55 52 4b 45 52 5f } //01 00 
		$a_01_2 = {3d 4d 46 00 00 } //01 00 
		$a_01_3 = {3d 44 44 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}