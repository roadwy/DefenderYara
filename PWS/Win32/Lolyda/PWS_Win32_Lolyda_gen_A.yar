
rule PWS_Win32_Lolyda_gen_A{
	meta:
		description = "PWS:Win32/Lolyda.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 05 00 00 "
		
	strings :
		$a_03_0 = {86 c4 c1 c0 10 86 c4 50 25 00 00 00 fc c1 c0 06 8a 80 ?? ?? ?? 10 aa 58 c1 e0 06 } //6
		$a_01_1 = {26 61 63 63 6f 75 6e 74 3d 25 73 } //1 &account=%s
		$a_01_2 = {26 70 61 73 73 77 6f 72 64 } //1 &password
		$a_01_3 = {70 6f 73 74 2e 61 73 70 } //1 post.asp
		$a_01_4 = {26 63 61 73 68 3d 25 73 } //1 &cash=%s
	condition:
		((#a_03_0  & 1)*6+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}