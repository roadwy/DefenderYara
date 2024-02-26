
rule Trojan_Win32_Alisa_GNW_MTB{
	meta:
		description = "Trojan:Win32/Alisa.GNW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 10 8b 44 24 14 89 54 24 18 99 2b c2 8b f8 8b c5 99 2b c2 8b 54 24 54 d1 ff d1 f8 2b c7 03 c8 8b 44 24 18 89 4c 24 1c 03 cd 03 c2 89 4c 24 24 8b 4c 24 70 89 44 24 20 8b 06 51 8b ce } //01 00 
		$a_80_1 = {43 4c 69 73 74 43 74 72 6c 5f 74 65 73 74 } //CListCtrl_test  00 00 
	condition:
		any of ($a_*)
 
}