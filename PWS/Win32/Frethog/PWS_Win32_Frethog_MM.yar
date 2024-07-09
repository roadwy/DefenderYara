
rule PWS_Win32_Frethog_MM{
	meta:
		description = "PWS:Win32/Frethog.MM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 6a 1a 68 ff ff 00 00 e8 ?? ?? ff ff a1 ?? ?? ?? ?? 50 e8 ?? ?? ff ff 84 db 0f 85 ?? ?? 00 00 6a 00 6a 00 6a 03 6a 00 6a 01 68 00 00 00 40 8d 45 e4 } //1
		$a_03_1 = {8b d8 83 fb ff 74 ?? 6a 00 6a 00 68 c0 c8 50 00 53 e8 ?? ?? ff ff b8 } //2
		$a_01_2 = {77 6f 77 2e 65 78 65 00 57 4f 57 44 4c 4c 00 } //1
		$a_01_3 = {48 6f 6f 6b 6f 6e 00 00 48 6f 6f 6b 6f 66 66 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}