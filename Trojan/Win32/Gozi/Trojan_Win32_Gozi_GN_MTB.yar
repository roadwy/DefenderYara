
rule Trojan_Win32_Gozi_GN_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {33 c9 03 c0 03 d0 8b c2 8a 35 90 01 04 13 f9 02 f0 4e 88 35 90 01 04 0f af f0 8b 4c 24 90 01 01 8a d3 8b 09 89 4c 24 90 01 01 8a cb c0 e1 90 01 01 02 d1 02 d0 88 15 90 01 04 3b 1d 90 01 04 72 90 01 01 8d 4b 90 01 01 02 f0 03 c8 88 35 90 00 } //01 00 
		$a_00_1 = {f3 a4 8b 44 24 0c 5e 5f c3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Gozi_GN_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8a 10 33 f6 56 88 95 90 01 04 53 45 e8 90 00 } //0a 00 
		$a_02_1 = {0f b6 d3 8d 54 02 90 01 01 8a c1 b1 90 01 01 f6 e9 f6 db 2a d8 66 0f b6 44 24 90 01 01 66 0f af c5 66 2b c7 0f b7 c8 8b 06 05 90 01 04 89 15 90 01 04 02 d1 89 06 80 ea 90 01 01 83 c6 90 01 01 83 6c 24 90 01 01 01 a3 90 01 04 88 54 24 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Gozi_GN_MTB_3{
	meta:
		description = "Trojan:Win32/Gozi.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {f3 0f 6f 01 8b 4c 24 54 0b 4c 24 54 90 02 0d 8b 74 24 14 01 ce f3 0f 6f 4a 90 01 05 f3 0f 7f 04 90 01 01 8a 5c 24 63 89 44 24 08 88 d8 90 01 04 88 44 24 63 8b 4c 24 08 f3 0f 7f 8c 0e 90 01 04 66 8b 7c 24 5a 8b 74 24 40 66 89 7c 24 5a 83 c6 90 01 01 8b 44 24 54 8b 4c 24 2c 83 f0 90 01 01 89 44 24 54 89 74 24 3c 39 ce 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}