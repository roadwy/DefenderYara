
rule Ransom_Win32_FileCrypt_A_MSR{
	meta:
		description = "Ransom:Win32/FileCrypt.A!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 59 68 53 30 59 61 71 78 64 6b 45 51 70 44 33 41 6b 75 63 67 2f 4c 47 44 6d 6f 6f 4d 57 78 43 55 36 38 67 57 6b 5f 41 6f 6d 2f 76 61 57 56 4a 32 53 54 44 79 30 69 5a 47 48 79 6f 4f 57 56 2f 47 4a 45 36 55 55 34 52 6f 56 54 30 67 72 2d 2d 52 30 4b 44 } //1 Go build ID: "YhS0YaqxdkEQpD3Akucg/LGDmooMWxCU68gWk_Aom/vaWVJ2STDy0iZGHyoOWV/GJE6UU4RoVT0gr--R0KD
		$a_01_1 = {43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 57 44 6e 73 4e 61 6d 65 43 6f 6d 70 61 72 65 5f 57 44 75 70 6c 69 63 61 74 65 54 6f 6b 65 6e 45 78 45 6e 63 72 79 70 74 4f 41 45 50 } //1 CreateDirectoryWDnsNameCompare_WDuplicateTokenExEncryptOAEP
		$a_01_2 = {35 74 79 6a 37 66 33 78 73 73 36 6b 64 72 67 63 2e 6f 6e 69 6f 6e } //1 5tyj7f3xss6kdrgc.onion
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}