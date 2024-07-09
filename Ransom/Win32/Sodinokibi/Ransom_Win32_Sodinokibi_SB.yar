
rule Ransom_Win32_Sodinokibi_SB{
	meta:
		description = "Ransom:Win32/Sodinokibi.SB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {53 65 72 76 69 63 65 43 72 74 4d 61 69 6e } //ServiceCrtMain  1
		$a_02_1 = {55 8b ec 83 ec 08 68 00 01 00 00 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? e8 } //1
		$a_02_2 = {8b 45 fc 89 45 f0 8b 4d ?? 83 c1 ?? 89 4d ?? 81 7d f0 ff 00 00 00 77 1f ba 01 00 00 00 6b c2 00 8b 4d ?? 0f b6 ?? ?? 33 55 ?? 89 55 ?? 83 7d f4 24 75 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}