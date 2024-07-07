
rule Trojan_Win32_Sopinar_F_bit{
	meta:
		description = "Trojan:Win32/Sopinar.F!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {0f b6 31 33 f0 81 e6 ff 00 00 00 c1 e8 08 33 04 b5 90 01 04 41 4a 75 e7 90 00 } //2
		$a_01_1 = {64 a1 30 00 00 00 8b 48 0c 8b 41 0c } //1
		$a_03_2 = {0f b6 08 33 ca 90 02 20 88 0a eb 90 00 } //1
		$a_01_3 = {c7 45 e8 72 00 6e 00 c7 45 ec 65 00 6c 00 c7 45 f0 33 00 32 00 c7 45 f4 2e 00 64 00 c7 45 f8 6c 00 6c 00 66 89 4d fc } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}