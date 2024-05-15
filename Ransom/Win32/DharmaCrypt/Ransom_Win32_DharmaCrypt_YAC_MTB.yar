
rule Ransom_Win32_DharmaCrypt_YAC_MTB{
	meta:
		description = "Ransom:Win32/DharmaCrypt.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c6 01 8b 8d 90 01 04 8d 3c 49 8d 14 7a f7 da 03 d0 0f af ca 90 00 } //01 00 
		$a_01_1 = {8b 85 a8 fe ff ff 33 85 f4 fe ff ff 8b 95 4c ff ff ff 89 85 } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}