
rule Trojan_Win32_Tibs_gen_G{
	meta:
		description = "Trojan:Win32/Tibs.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {89 c7 f3 a4 61 83 c0 90 03 01 01 04 05 ff e0 8b bd 90 01 04 03 bd 90 01 04 8d b5 90 01 04 8b 8d 90 01 04 68 00 10 00 00 57 e8 8a 01 00 00 f3 a4 90 00 } //1
		$a_03_1 = {89 c7 f3 a4 61 90 03 05 04 83 c0 90 01 01 05 90 01 04 ff e0 60 8b bd 90 01 04 03 bd 90 01 04 8d b5 90 01 04 8b 8d 90 01 04 68 00 10 00 00 57 e8 90 01 02 00 00 f3 a4 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}