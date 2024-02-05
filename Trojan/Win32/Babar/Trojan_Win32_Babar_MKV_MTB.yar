
rule Trojan_Win32_Babar_MKV_MTB{
	meta:
		description = "Trojan:Win32/Babar.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b e9 c1 ed 90 01 01 81 e5 90 01 04 81 e6 90 01 04 30 8b 90 01 04 29 3e 6c 24 30 33 a3 90 01 04 da c1 eb 90 01 01 33 74 9d 00 a3 05 1c 8b df 2f 02 5c 00 00 a3 90 01 04 10 c1 eb 90 01 01 8b e9 89 4c 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}