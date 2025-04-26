
rule Backdoor_Win32_Unomois_A{
	meta:
		description = "Backdoor:Win32/Unomois.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 00 65 00 30 00 68 00 6f 00 69 00 } //1 me0hoi
		$a_00_1 = {8b d8 83 e1 03 c1 e1 04 c1 eb 04 0b d9 } //1
		$a_00_2 = {88 07 88 4f 01 83 c5 03 83 c7 04 83 ea 01 } //1
		$a_00_3 = {0f b6 50 01 0f b6 78 02 83 e2 0f 03 d2 03 d2 c1 ef 06 0b d7 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}