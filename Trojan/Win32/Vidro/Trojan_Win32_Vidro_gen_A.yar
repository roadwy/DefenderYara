
rule Trojan_Win32_Vidro_gen_A{
	meta:
		description = "Trojan:Win32/Vidro.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {69 d2 6d 4e c6 41 81 c2 93 30 00 00 89 55 fc c1 ca 08 0f b6 d2 2b c2 05 8c 03 00 00 6a 5e 99 5e f7 fe 80 c2 20 } //1
		$a_02_1 = {83 f8 05 0f 8c 90 01 04 8b 07 80 38 23 75 90 01 01 81 78 01 65 6e 63 23 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}