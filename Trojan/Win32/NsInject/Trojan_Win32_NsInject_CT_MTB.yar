
rule Trojan_Win32_NsInject_CT_MTB{
	meta:
		description = "Trojan:Win32/NsInject.CT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c9 8d a4 24 00 00 00 00 8a 14 8d 90 01 04 80 c2 90 01 01 88 14 01 83 c1 01 81 f9 90 01 02 00 00 7c e8 8d 0c 24 51 05 90 01 02 00 00 ff d0 b8 90 01 02 00 00 83 c4 1c c3 90 00 } //01 00 
		$a_02_1 = {8b 4c 24 04 33 c0 eb 90 01 01 8d a4 24 00 00 00 00 90 05 10 01 90 8a 14 85 90 01 04 80 c2 90 01 01 88 14 08 83 c0 01 3d 90 01 02 00 00 7c 90 01 01 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}