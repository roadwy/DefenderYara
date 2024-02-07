
rule Ransom_Win32_Gandcrab_AHB_MTB{
	meta:
		description = "Ransom:Win32/Gandcrab.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {8a 84 0e 32 09 00 00 90 02 0a 88 04 39 90 00 } //01 00 
		$a_03_1 = {30 06 c3 55 90 0a 0c 00 90 90 90 90 90 90 90 90 90 90 90 00 } //01 00 
		$a_03_2 = {30 04 1f 56 ff 90 02 05 56 ff 90 02 05 33 c0 90 02 0f ab 90 00 } //02 00 
		$a_03_3 = {8a 84 32 e1 bf 01 00 8b 0d 90 01 04 88 04 31 a1 90 01 04 46 3b f0 72 90 00 } //01 00 
		$a_03_4 = {30 0c 37 83 ee 01 0f 89 90 0a 2f 00 81 84 24 90 01 08 81 6c 24 90 02 08 81 84 24 90 00 } //00 00 
		$a_00_5 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}