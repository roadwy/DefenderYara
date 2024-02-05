
rule Trojan_Win32_Strab_CB_MTB{
	meta:
		description = "Trojan:Win32/Strab.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {3d a1 06 00 00 74 12 40 3d 86 76 13 01 89 44 24 10 0f 8c } //02 00 
		$a_03_1 = {8d 14 33 33 c2 33 44 24 10 81 c3 90 02 04 2b f8 83 6c 24 18 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}