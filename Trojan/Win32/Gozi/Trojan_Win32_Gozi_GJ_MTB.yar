
rule Trojan_Win32_Gozi_GJ_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8d 44 01 03 33 c9 a3 90 01 04 89 0d 90 01 04 8b 45 90 01 01 69 c0 90 01 04 0f b6 0d 90 01 04 2b c1 a2 90 01 04 0f b6 05 90 01 04 8b 4d 90 01 01 8d 44 08 90 01 01 89 45 90 01 01 ff 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Gozi_GJ_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {29 18 8b 3d 90 01 04 0f b6 ca 03 ce 8d 73 90 01 01 03 f1 8a cb c0 e1 90 01 01 2a cb c0 e1 90 01 01 2a ca 8a d1 88 15 90 01 04 83 e8 04 3d 90 01 04 7f 90 00 } //0a 00 
		$a_02_1 = {89 02 83 c2 04 a3 90 01 04 8a c1 c0 e0 90 01 01 02 c1 89 54 24 90 01 01 8a 0d 90 01 04 02 c0 2a c8 83 6c 24 90 01 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}