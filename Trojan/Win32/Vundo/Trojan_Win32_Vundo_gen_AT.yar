
rule Trojan_Win32_Vundo_gen_AT{
	meta:
		description = "Trojan:Win32/Vundo.gen!AT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 1a 8d 45 84 50 6a 00 8b f1 ff 15 90 01 04 8d 45 84 50 90 01 1d 59 6a 08 5f 90 00 } //1
		$a_03_1 = {83 f8 50 74 1d 50 8d 45 dc 68 90 01 04 50 ff 15 90 00 } //1
		$a_01_2 = {72 02 33 d2 8a 04 0e 32 04 3a 88 01 41 42 4b 75 ec } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}