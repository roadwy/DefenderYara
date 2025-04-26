
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
rule Ransom_Win32_Sodinokibi_SB_2{
	meta:
		description = "Ransom:Win32/Sodinokibi.SB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b 65 78 70 61 6e 64 20 31 36 2d 62 79 74 65 20 6b } //expand 32-byte kexpand 16-byte k  1
		$a_03_1 = {53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 41 00 63 00 74 00 69 00 76 00 65 00 90 2c 01 09 30 2d 39 41 2d 5a 61 2d 7a 90 09 02 00 90 2c 01 09 30 2d 39 41 2d 5a 61 2d 7a } //1
		$a_80_2 = {43 72 65 61 74 65 54 68 72 65 61 64 } //CreateThread  1
		$a_80_3 = {47 65 74 45 78 69 74 43 6f 64 65 50 72 6f 63 65 73 73 } //GetExitCodeProcess  1
		$a_80_4 = {43 6c 6f 73 65 48 61 6e 64 6c 65 } //CloseHandle  1
		$a_80_5 = {53 65 74 45 72 72 6f 72 4d 6f 64 65 } //SetErrorMode  1
		$a_80_6 = {3a 21 3a 28 3a 2f 3a 36 3a 43 3a 5c 3a 6d 3a } //:!:(:/:6:C:\:m:  1
	condition:
		((#a_80_0  & 1)*1+(#a_03_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}