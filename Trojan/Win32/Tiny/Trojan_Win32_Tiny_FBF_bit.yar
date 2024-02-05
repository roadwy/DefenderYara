
rule Trojan_Win32_Tiny_FBF_bit{
	meta:
		description = "Trojan:Win32/Tiny.FBF!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 55 00 01 da 83 c2 0c 31 0a 3b 85 90 01 04 73 08 83 c0 04 83 c3 04 eb e6 90 00 } //01 00 
		$a_03_1 = {80 7c 03 ff c3 74 02 eb 90 01 01 8b 45 00 83 c0 0c ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}