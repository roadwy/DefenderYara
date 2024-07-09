
rule Trojan_Win32_Prepscram_A_MTB{
	meta:
		description = "Trojan:Win32/Prepscram.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {0f b6 8c 35 ?? ?? ?? ?? 0f b6 c2 03 c8 81 e1 ff 00 00 00 0f b6 84 0d ?? ?? ?? ?? 8b 4d f8 30 44 0f ff 3b 7d fc } //1
		$a_80_1 = {43 54 53 2e 65 78 65 } //CTS.exe  1
		$a_80_2 = {33 70 63 36 52 57 4f 67 65 63 74 47 54 46 71 43 6f 77 78 6a 65 47 79 33 58 49 47 50 74 4c 77 4e 72 73 72 32 7a 44 63 74 59 44 34 68 41 55 35 70 6a 34 47 57 37 72 6d 38 67 48 72 48 79 54 42 36 } //3pc6RWOgectGTFqCowxjeGy3XIGPtLwNrsr2zDctYD4hAU5pj4GW7rm8gHrHyTB6  1
	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}