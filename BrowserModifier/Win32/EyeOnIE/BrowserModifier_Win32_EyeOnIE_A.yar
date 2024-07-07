
rule BrowserModifier_Win32_EyeOnIE_A{
	meta:
		description = "BrowserModifier:Win32/EyeOnIE.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {42 68 6f 50 6c 75 67 69 6e 2e 45 79 65 4f 6e 49 45 2e 31 90 09 0a 00 48 4b 43 52 0d 0a 7b 0d 0a 09 90 00 } //1
		$a_00_1 = {7b 36 45 32 38 33 33 39 42 2d 37 41 32 41 2d 34 37 42 36 2d 41 45 42 32 2d 34 36 42 41 35 33 37 38 32 33 37 39 7d } //1 {6E28339B-7A2A-47B6-AEB2-46BA53782379}
		$a_01_2 = {77 77 77 00 77 77 00 00 77 00 00 00 77 77 77 2e 00 00 00 00 68 74 74 70 3a 2f 2f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}