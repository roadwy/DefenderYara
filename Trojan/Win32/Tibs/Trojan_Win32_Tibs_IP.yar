
rule Trojan_Win32_Tibs_IP{
	meta:
		description = "Trojan:Win32/Tibs.IP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {fe 7f 81 fa 00 90 04 01 03 90 90 a0 00 00 7f 90 09 04 00 8b 90 04 01 03 90 90 15 00 90 00 } //01 00 
		$a_03_1 = {c3 55 89 e5 83 ec 04 c7 45 fc 90 01 04 c7 45 fc 90 01 04 ab c9 c3 90 09 07 00 e8 90 01 01 00 00 00 e2 90 00 } //01 00 
		$a_03_2 = {83 c0 ff ba 90 01 04 c1 c2 90 09 0b 00 b9 90 01 04 81 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}