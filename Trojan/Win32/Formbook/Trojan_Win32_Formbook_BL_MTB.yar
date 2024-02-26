
rule Trojan_Win32_Formbook_BL_MTB{
	meta:
		description = "Trojan:Win32/Formbook.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 55 ff c1 fa 03 0f b6 45 ff c1 e0 05 0b d0 0f b6 4d fe 33 d1 8b 45 f8 88 90 c0 75 42 00 } //01 00 
		$a_01_1 = {68 74 64 6f 63 73 5c 64 61 63 32 34 38 64 35 32 32 37 65 34 37 38 62 39 39 36 65 32 63 65 32 33 39 63 35 36 32 64 39 } //00 00  htdocs\dac248d5227e478b996e2ce239c562d9
	condition:
		any of ($a_*)
 
}