
rule Trojan_Win32_ClickFix_FFL_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.FFL!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {69 00 65 00 78 00 20 00 28 00 69 00 72 00 6d 00 20 00 68 00 74 00 74 00 70 00 } //1 iex (irm http
		$a_00_1 = {2e 00 69 00 6e 00 6b 00 } //1 .ink
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule Trojan_Win32_ClickFix_FFL_MTB_2{
	meta:
		description = "Trojan:Win32/ClickFix.FFL!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {7c 00 20 00 49 00 45 00 58 00 26 00 23 00 } //1 | IEX&#
		$a_00_1 = {2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //1 .DownloadString
		$a_00_2 = {4e 00 65 00 74 00 2e 00 57 00 65 00 62 00 43 00 6c 00 69 00 65 00 6e 00 74 00 } //1 Net.WebClient
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule Trojan_Win32_ClickFix_FFL_MTB_3{
	meta:
		description = "Trojan:Win32/ClickFix.FFL!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {52 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 5d 00 3a 00 3a 00 4c 00 6f 00 61 00 64 00 } //1 Reflection.Assembly]::Load
		$a_00_1 = {5b 00 43 00 6f 00 6e 00 76 00 65 00 72 00 74 00 5d 00 3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //1 [Convert]::FromBase64String
		$a_00_2 = {4e 00 65 00 74 00 2e 00 57 00 65 00 62 00 43 00 6c 00 69 00 65 00 6e 00 74 00 } //1 Net.WebClient
		$a_00_3 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //1 DownloadString
		$a_00_4 = {2e 00 47 00 65 00 74 00 4d 00 65 00 74 00 68 00 6f 00 64 00 } //1 .GetMethod
		$a_00_5 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 28 00 24 00 } //1 invoke($
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}
rule Trojan_Win32_ClickFix_FFL_MTB_4{
	meta:
		description = "Trojan:Win32/ClickFix.FFL!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {69 00 65 00 78 00 28 00 24 00 } //1 iex($
		$a_00_1 = {2e 00 52 00 65 00 73 00 75 00 6c 00 74 00 2e 00 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2e 00 52 00 65 00 61 00 64 00 41 00 73 00 53 00 74 00 72 00 69 00 6e 00 67 00 41 00 73 00 79 00 6e 00 63 00 28 00 } //1 .Result.Content.ReadAsStringAsync(
		$a_00_2 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 4e 00 65 00 74 00 2e 00 48 00 74 00 74 00 70 00 2e 00 53 00 74 00 72 00 69 00 6e 00 67 00 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 } //1 System.Net.Http.StringContent
		$a_00_3 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 4e 00 65 00 74 00 2e 00 48 00 74 00 74 00 70 00 2e 00 48 00 74 00 74 00 70 00 43 00 6c 00 69 00 65 00 6e 00 74 00 } //1 System.Net.Http.HttpClient
		$a_00_4 = {50 00 6f 00 73 00 74 00 41 00 73 00 79 00 6e 00 63 00 28 00 } //1 PostAsync(
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}