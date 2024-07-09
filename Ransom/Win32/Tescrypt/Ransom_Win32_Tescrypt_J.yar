
rule Ransom_Win32_Tescrypt_J{
	meta:
		description = "Ransom:Win32/Tescrypt.J,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 "
		
	strings :
		$a_03_0 = {3d c7 04 00 00 75 15 68 34 08 00 00 ff 15 ?? ?? ?? ?? 8d 45 c0 50 ff d6 85 c0 74 de } //1
		$a_01_1 = {76 73 73 61 00 } //1
		$a_01_2 = {00 64 6d 69 6e 00 } //1 搀業n
		$a_01_3 = {73 68 61 64 6f 77 73 } //1 shadows
		$a_01_4 = {2f 61 6c 6c } //1 /all
		$a_01_5 = {2f 51 75 69 65 74 } //1 /Quiet
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}