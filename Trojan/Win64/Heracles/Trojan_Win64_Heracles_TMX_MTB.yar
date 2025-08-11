
rule Trojan_Win64_Heracles_TMX_MTB{
	meta:
		description = "Trojan:Win64/Heracles.TMX!MTB,SIGNATURE_TYPE_PEHSTR,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {24 38 35 42 41 30 44 46 43 2d 37 34 36 44 2d 34 32 39 32 2d 39 39 37 43 2d 39 45 46 41 45 32 39 43 41 35 37 46 } //4 $85BA0DFC-746D-4292-997C-9EFAE29CA57F
		$a_01_1 = {43 3a 5c 77 65 62 76 69 65 77 32 5c 77 65 62 76 69 65 77 32 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 77 65 62 76 69 65 77 32 2e 70 64 62 } //4 C:\webview2\webview2\obj\Release\webview2.pdb
		$a_01_2 = {50 61 6c 69 6e 64 72 6f 6d 65 } //1 Palindrome
		$a_01_3 = {46 61 68 72 65 6e 68 65 69 74 } //1 Fahrenheit
		$a_01_4 = {47 65 74 52 61 6e 64 6f 6d 57 6f 72 64 } //1 GetRandomWord
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}