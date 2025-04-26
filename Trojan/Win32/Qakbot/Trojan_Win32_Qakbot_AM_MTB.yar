
rule Trojan_Win32_Qakbot_AM_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 6f 33 6a 43 6e 53 61 71 } //2 Co3jCnSaq
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //2 DllRegisterServer
		$a_01_2 = {45 4d 62 76 46 5a 4d 69 64 64 } //2 EMbvFZMidd
		$a_01_3 = {45 51 34 65 50 62 } //2 EQ4ePb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}
rule Trojan_Win32_Qakbot_AM_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {42 68 79 38 2e 64 6c 6c } //1 Bhy8.dll
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_01_2 = {41 64 64 46 6f 6e 74 52 65 73 6f 75 72 63 65 57 } //1 AddFontResourceW
		$a_01_3 = {43 72 65 61 74 65 44 49 42 50 61 74 74 65 72 6e 42 72 75 73 68 50 74 } //1 CreateDIBPatternBrushPt
		$a_01_4 = {47 65 74 43 68 61 72 41 42 43 57 69 64 74 68 73 41 } //1 GetCharABCWidthsA
		$a_01_5 = {47 65 74 47 6c 79 70 68 4f 75 74 6c 69 6e 65 41 } //1 GetGlyphOutlineA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}