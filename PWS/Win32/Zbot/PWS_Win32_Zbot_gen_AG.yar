
rule PWS_Win32_Zbot_gen_AG{
	meta:
		description = "PWS:Win32/Zbot.gen!AG,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {68 ae 33 39 80 5f 81 c7 e8 03 00 00 89 e3 } //1
		$a_03_1 = {12 01 d9 d0 bb 90 01 04 8b 1b 81 c3 06 00 00 00 e8 90 01 04 eb 90 01 01 55 89 e5 51 ff e3 90 00 } //1
		$a_01_2 = {31 db 29 c3 89 d8 a3 } //1
		$a_01_3 = {55 50 58 21 } //1 UPX!
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}