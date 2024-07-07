
rule Virus_Win32_Dundun_gen_A{
	meta:
		description = "Virus:Win32/Dundun.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {8b 7d b5 33 c0 33 c9 49 f2 ae 81 7f fb 2e 45 58 45 74 0d 81 7f fb 2e 65 78 65 0f 85 34 02 00 00 68 80 00 00 00 ff 74 24 34 ff 55 64 85 c0 } //1
		$a_00_1 = {8b f9 51 50 33 c0 6a 14 59 fc f3 ab 58 59 c7 01 44 45 4e 47 c7 41 04 20 44 55 4e ff 75 04 8f 41 08 } //1
		$a_02_2 = {f3 a4 83 c6 6c 6a 70 59 f3 a4 8b 85 e0 00 00 00 66 8b d8 c1 e8 10 5e 03 75 bd b9 90 01 02 00 00 30 1e 30 3e 30 06 30 26 46 e2 f5 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}