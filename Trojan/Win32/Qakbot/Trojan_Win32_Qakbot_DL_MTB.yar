
rule Trojan_Win32_Qakbot_DL_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2d 80 0d 00 00 03 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 03 45 90 01 01 8b 55 90 01 01 31 02 6a 00 e8 90 01 04 8b d8 8b 45 9c 83 c0 04 03 d8 6a 00 e8 90 01 04 2b d8 6a 00 e8 90 01 04 03 d8 6a 00 e8 90 01 04 2b d8 6a 00 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_DL_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6b 3f 30 3f 24 43 61 63 68 65 4b 65 79 40 56 44 61 74 65 46 6d 74 42 65 73 74 50 61 74 74 65 72 6e 40 69 63 75 5f 35 37 40 40 40 69 63 75 5f 35 37 40 40 51 41 45 40 41 42 56 30 31 40 40 5a } //1 k?0?$CacheKey@VDateFmtBestPattern@icu_57@@@icu_57@@QAE@ABV01@@Z
		$a_01_1 = {6b 3f 30 43 75 72 72 65 6e 63 79 50 6c 75 72 61 6c 49 6e 66 6f 40 69 63 75 5f 35 37 40 40 51 41 45 40 41 42 56 30 31 40 40 5a } //1 k?0CurrencyPluralInfo@icu_57@@QAE@ABV01@@Z
		$a_01_2 = {6b 3f 30 43 6f 6c 6c 61 74 69 6f 6e 57 65 69 67 68 74 73 40 69 63 75 5f 35 37 40 40 51 41 45 40 58 5a } //1 k?0CollationWeights@icu_57@@QAE@XZ
		$a_01_3 = {6b 3f 30 3f 24 50 6c 75 72 61 6c 4d 61 70 40 56 44 69 67 69 74 41 66 66 69 78 40 69 63 75 5f 35 37 40 40 40 69 63 75 5f 35 37 40 40 51 41 45 40 58 5a } //1 k?0?$PluralMap@VDigitAffix@icu_57@@@icu_57@@QAE@XZ
		$a_01_4 = {6d 6f 72 65 } //1 more
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}