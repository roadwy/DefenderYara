
rule Trojan_Win32_Zenpak_AX_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {89 d7 01 f7 81 c7 90 02 04 69 f0 88 00 00 00 01 f2 81 c2 90 02 04 05 01 00 00 00 8b 12 0f b7 37 31 d6 01 ce 3d c0 00 00 00 89 f1 89 4d cc 89 75 c4 89 45 c8 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}