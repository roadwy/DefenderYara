
rule Trojan_Win32_Stealer_A_MTB{
	meta:
		description = "Trojan:Win32/Stealer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {8a 44 0c 20 2c 21 88 84 0c cc 00 00 00 41 3b ca 7c ee } //1
		$a_01_1 = {8a 44 0c 10 34 55 88 44 0c 2c 41 83 f9 0a 7c f0 } //1
		$a_01_2 = {0f b6 44 0c 10 66 03 c2 66 23 c6 66 89 84 4c 64 01 00 00 41 83 f9 0c 7c e7 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}