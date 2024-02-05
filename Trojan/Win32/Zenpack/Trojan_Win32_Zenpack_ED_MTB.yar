
rule Trojan_Win32_Zenpack_ED_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {5d c3 8d 05 90 01 04 89 25 90 01 04 eb 05 e9 90 01 04 89 da 01 15 90 01 04 89 f0 01 05 90 01 04 b9 03 00 00 00 89 e8 01 05 90 01 04 89 f8 01 90 01 05 e2 d4 c3 89 45 90 00 } //01 00 
		$a_01_1 = {72 65 74 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}