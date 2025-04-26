
rule Trojan_Win32_Pincav_ARA_MTB{
	meta:
		description = "Trojan:Win32/Pincav.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 82 60 12 40 00 83 f0 d8 88 06 46 42 83 fa 26 75 ee } //2
		$a_01_1 = {30 1a 42 89 c8 03 84 24 6d 01 00 00 39 d0 77 f0 } //2
		$a_01_2 = {30 58 ff 40 39 d0 75 f8 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}