
rule Trojan_Win32_Zusy_GCI_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GCI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {33 c0 b1 61 eb 90 01 01 8d a4 24 90 01 04 30 88 90 01 04 40 3d bc 02 00 00 72 90 00 } //0a 00 
		$a_03_1 = {72 88 5c 24 90 01 01 c6 44 24 90 01 01 61 c6 44 24 90 01 01 74 88 5c 24 90 01 01 c6 44 24 90 01 01 74 88 44 24 90 01 01 c6 44 24 90 01 01 54 c6 44 24 90 01 01 68 c6 44 24 90 01 01 72 88 5c 24 90 01 01 c6 44 24 90 01 01 61 c6 44 24 90 01 01 64 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}