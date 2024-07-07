
rule Trojan_Win32_Vundo_gen_AQ{
	meta:
		description = "Trojan:Win32/Vundo.gen!AQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {30 11 ff 45 90 01 01 39 45 90 01 01 7c 90 00 } //2
		$a_01_1 = {0f b7 40 16 66 a9 00 20 74 09 } //2
		$a_03_2 = {75 06 c6 04 32 5c eb 08 3c 90 01 01 75 07 c6 04 32 22 90 00 } //1
		$a_01_3 = {d3 f8 47 32 45 0f 88 04 32 42 43 83 fb 04 7c 02 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}