
rule Trojan_Win32_Viknok_C{
	meta:
		description = "Trojan:Win32/Viknok.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_81_0 = {70 3d 25 75 26 74 3d 25 75 26 65 3d 25 75 } //01 00 
		$a_03_1 = {8b 42 3c 03 c2 8b 78 78 89 45 90 01 01 85 ff 74 90 01 01 83 65 90 01 01 00 03 fa 8b 4f 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}