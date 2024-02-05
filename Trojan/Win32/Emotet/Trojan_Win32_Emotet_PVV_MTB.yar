
rule Trojan_Win32_Emotet_PVV_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PVV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 c9 03 c1 99 b9 05 17 00 00 f7 f9 0f b6 94 15 90 01 04 30 53 ff 90 09 1e 00 0f b6 94 3d 90 01 04 88 94 35 90 01 04 88 8c 3d 90 01 04 0f b6 84 35 90 00 } //01 00 
		$a_00_1 = {63 6c 6f 57 43 51 62 64 43 4a 6c 38 55 53 34 56 44 64 4c 51 34 53 77 79 69 63 63 39 41 73 35 62 34 31 4d 61 36 4d 4f 48 64 42 4f } //00 00 
	condition:
		any of ($a_*)
 
}