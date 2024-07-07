
rule Trojan_Win32_CryptInject_ART_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.ART!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {50 48 73 20 50 48 73 32 50 48 73 46 50 48 73 58 50 48 73 6c 50 48 73 7e 50 48 73 } //1 PHs PHs2PHsFPHsXPHslPHs~PHs
		$a_01_1 = {47 73 38 4c 48 73 7a 4a 48 73 2e 42 48 73 3e 42 48 73 5b 42 48 73 6d 42 48 73 } //1 Gs8LHszJHs.BHs>BHs[BHsmBHs
		$a_01_2 = {51 48 73 2a 51 48 73 3c 51 48 73 50 51 48 73 62 51 48 73 76 51 48 73 } //1 QHs*QHs<QHsPQHsbQHsvQHs
		$a_01_3 = {52 48 73 20 52 48 73 34 52 48 73 46 52 48 73 5a 52 48 73 6c 52 48 73 } //1 RHs RHs4RHsFRHsZRHslRHs
		$a_01_4 = {74 61 76 65 72 6e 48 6f 74 65 6c 44 69 72 65 63 74 6f 72 79 53 79 73 74 65 6d 2e 4d 61 69 6c 34 36 55 43 } //1 tavernHotelDirectorySystem.Mail46UC
		$a_01_5 = {56 48 73 22 56 48 73 36 56 48 73 48 56 48 73 5c 56 48 73 6e 56 48 73 } //1 VHs"VHs6VHsHVHs\VHsnVHs
		$a_03_6 = {66 0f b6 04 11 90 02 4f 2b 42 14 89 85 90 02 04 8b 0d 90 02 4f 66 81 c2 00 01 90 02 4f 8b 85 90 02 04 66 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1) >=6
 
}