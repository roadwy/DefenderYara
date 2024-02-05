
rule Trojan_Win32_Cridex_DAF_MTB{
	meta:
		description = "Trojan:Win32/Cridex.DAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b d1 2b d3 81 c2 90 1e 00 00 0f b7 da 0f b7 d3 2b 15 90 01 04 81 c5 90 01 04 89 28 83 c0 04 83 6c 24 14 01 8d 7c 17 e9 89 44 24 10 90 00 } //01 00 
		$a_00_1 = {8b d1 2b d3 81 c2 90 1e 00 00 0f b7 da 0f b7 d3 2b 15 c0 c0 02 10 81 c5 28 2d 03 01 89 28 83 c0 04 83 6c 24 14 01 8d 7c 17 e9 89 44 24 10 } //00 00 
	condition:
		any of ($a_*)
 
}