
rule Trojan_Win32_Barys_GXV_MTB{
	meta:
		description = "Trojan:Win32/Barys.GXV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 16 07 1c f3 67 54 35 90 01 04 45 56 f6 2f 2f 16 f6 62 38 6c 90 00 } //05 00 
		$a_01_1 = {f6 3f 04 d4 20 37 8b 52 e1 35 2f 5d c3 4a } //00 00 
	condition:
		any of ($a_*)
 
}