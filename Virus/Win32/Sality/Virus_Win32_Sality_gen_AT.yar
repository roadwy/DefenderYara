
rule Virus_Win32_Sality_gen_AT{
	meta:
		description = "Virus:Win32/Sality.gen!AT,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 3a 2f 2f 6b 75 6b 75 [0-0f] 2e 69 6e 66 6f } //1
		$a_02_1 = {2e 69 6e 66 6f 2f 68 6f 6d 65 2e 67 69 66 00 68 74 74 70 3a 2f 2f [0-15] 2e 69 6e 66 6f 2f 68 6f 6d 65 2e 67 69 66 } //1
		$a_03_2 = {60 e8 00 00 00 00 90 17 08 01 01 01 01 01 01 01 01 58 59 5a 5b 5c 5d 5e 5f 81 ?? ?? ?? ?? ?? 90 17 08 01 01 01 01 01 01 01 01 50 51 52 53 54 55 56 57 [0-10] c3 } //2
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_03_2  & 1)*2) >=3
 
}
rule Virus_Win32_Sality_gen_AT_2{
	meta:
		description = "Virus:Win32/Sality.gen!AT,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 75 72 69 74 79 5f 63 6f 6e 74 72 6f 6c } //1 purity_control
		$a_01_1 = {66 81 3a 4d 5a 0f 85 54 02 00 00 8b 42 3c 03 d0 66 81 3a 50 45 0f 85 44 02 00 00 } //1
		$a_03_2 = {8b 6d 08 80 bd ?? ?? ?? ?? 01 0f 85 fb 00 00 00 8b 8d ?? ?? ?? ?? 49 85 c9 74 0f 41 8d b5 ?? ?? ?? ?? 8b bd ?? ?? ?? ?? f3 a4 89 ad ?? ?? ?? ?? 89 ad ?? ?? ?? ?? 89 ad ?? ?? ?? ?? 89 ad ?? ?? ?? ?? 89 ad ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 68 fe 01 00 00 50 6a 00 ff 95 ?? ?? ?? ?? 85 c0 74 2e 8b c8 48 83 bc 05 ?? ?? ?? ?? 00 74 10 80 bc 05 ?? ?? ?? ?? 5c } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}