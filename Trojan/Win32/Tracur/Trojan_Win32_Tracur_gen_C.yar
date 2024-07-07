
rule Trojan_Win32_Tracur_gen_C{
	meta:
		description = "Trojan:Win32/Tracur.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {76 1b 8a 96 90 01 04 30 14 19 83 c6 01 3b f0 7c 02 33 f6 90 00 } //1
		$a_00_1 = {ff d5 24 7f 04 30 3c 61 7c 04 3c 7a 7e 12 3c 41 7c 04 3c 5a 7e 0a 8a c8 80 e9 30 80 f9 09 77 0a } //1
		$a_00_2 = {43 32 31 32 33 34 44 33 2d 35 43 43 32 2d 34 62 64 64 2d 39 42 45 37 2d 38 32 41 33 34 45 46 33 46 41 45 30 } //1 C21234D3-5CC2-4bdd-9BE7-82A34EF3FAE0
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}