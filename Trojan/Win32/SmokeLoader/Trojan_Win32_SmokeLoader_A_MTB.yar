
rule Trojan_Win32_SmokeLoader_A_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 44 24 24 8b 44 24 24 89 44 24 20 8b 54 24 18 8b 4c 24 1c d3 ea 89 54 24 14 8b 44 24 34 01 44 24 14 8b 44 24 20 31 44 24 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_SmokeLoader_A_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 dc 01 45 fc 8b 55 f8 8b 4d f4 8b c2 d3 e8 8d 34 17 81 c7 47 86 c8 61 03 45 e4 33 c6 31 45 fc 2b 5d fc ff 4d ec 0f 85 01 ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_SmokeLoader_A_MTB_3{
	meta:
		description = "Trojan:Win32/SmokeLoader.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {6d 69 64 65 7a 6f 79 6f 62 75 67 61 6c 6f 64 6f 6c 6f 62 75 76 65 6c 65 6c 65 7a 6f 63 6f 6b 61 6b 75 66 6f 66 61 66 61 63 61 } //1 midezoyobugalodolobuvelelezocokakufofafaca
		$a_81_1 = {73 65 67 6f 70 65 7a 65 68 75 79 6f 72 6f 73 65 63 65 } //1 segopezehuyorosece
		$a_81_2 = {6b 6b 75 72 69 6b 6f 6c 69 73 69 64 75 64 69 67 75 79 69 6b } //1 kkurikolisidudiguyik
		$a_81_3 = {53 6f 6c 6f 66 75 64 69 20 67 6f 78 6f 72 75 76 20 73 61 70 6f 63 75 7a 69 } //1 Solofudi goxoruv sapocuzi
		$a_81_4 = {61 6c 6c 6f 63 61 20 77 61 73 20 63 6f 72 72 75 70 74 65 64 } //1 alloca was corrupted
		$a_81_5 = {66 3a 5c 64 64 5c 76 63 74 } //1 f:\dd\vct
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}
rule Trojan_Win32_SmokeLoader_A_MTB_4{
	meta:
		description = "Trojan:Win32/SmokeLoader.A!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,5e 00 5e 00 0d 00 00 "
		
	strings :
		$a_00_0 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 4e 00 65 00 74 00 2e 00 57 00 65 00 62 00 50 00 72 00 6f 00 78 00 79 00 } //10 System.Net.WebProxy
		$a_00_1 = {57 00 65 00 62 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00 53 00 65 00 73 00 73 00 69 00 6f 00 6e 00 } //10 WebRequestSession
		$a_00_2 = {68 00 74 00 74 00 70 00 } //10 http
		$a_00_3 = {47 00 65 00 74 00 2d 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 56 00 61 00 6c 00 75 00 65 00 } //10 Get-RegistryValue
		$a_00_4 = {77 00 68 00 69 00 6c 00 65 00 20 00 28 00 24 00 } //10 while ($
		$a_00_5 = {2e 00 53 00 74 00 61 00 72 00 74 00 73 00 57 00 69 00 74 00 68 00 28 00 } //10 .StartsWith(
		$a_00_6 = {5b 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 54 00 65 00 78 00 74 00 2e 00 45 00 6e 00 63 00 6f 00 64 00 69 00 6e 00 67 00 5d 00 3a 00 3a 00 55 00 54 00 46 00 38 00 2e 00 47 00 65 00 74 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 24 00 } //10 [System.Text.Encoding]::UTF8.GetString($
		$a_00_7 = {42 00 79 00 74 00 65 00 5b 00 5d 00 } //10 Byte[]
		$a_00_8 = {2e 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 } //10 .content
		$a_00_9 = {69 00 77 00 72 00 20 00 } //3 iwr 
		$a_00_10 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 77 00 65 00 62 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 } //3 invoke-webrequest
		$a_00_11 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 65 00 78 00 70 00 72 00 65 00 73 00 73 00 69 00 6f 00 6e 00 20 00 24 00 } //1 invoke-expression $
		$a_00_12 = {69 00 65 00 78 00 20 00 24 00 } //1 iex $
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*10+(#a_00_6  & 1)*10+(#a_00_7  & 1)*10+(#a_00_8  & 1)*10+(#a_00_9  & 1)*3+(#a_00_10  & 1)*3+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1) >=94
 
}