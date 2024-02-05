
rule Ransom_Win32_Sodinokibi_SB{
	meta:
		description = "Ransom:Win32/Sodinokibi.SB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_80_0 = {53 65 72 76 69 63 65 43 72 74 4d 61 69 6e } //ServiceCrtMain  01 00 
		$a_02_1 = {55 8b ec 83 ec 08 68 00 01 00 00 ff 15 90 01 04 50 ff 15 90 01 04 a1 90 01 04 50 68 90 01 04 e8 90 00 } //01 00 
		$a_02_2 = {8b 45 fc 89 45 f0 8b 4d 90 01 01 83 c1 90 01 01 89 4d 90 01 01 81 7d f0 ff 00 00 00 77 1f ba 01 00 00 00 6b c2 00 8b 4d 90 01 01 0f b6 90 01 02 33 55 90 01 01 89 55 90 01 01 83 7d f4 24 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}