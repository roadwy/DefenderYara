
rule Trojan_Win32_Fivfrom_gen_A{
	meta:
		description = "Trojan:Win32/Fivfrom.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 04 10 a2 90 01 04 a1 90 01 04 b9 03 00 00 00 99 f7 f9 a0 90 01 04 2a c2 40 a2 90 01 04 6a 00 68 90 01 04 6a 01 68 90 01 04 a1 90 01 04 50 e8 90 01 04 ff 05 90 01 04 81 3d 90 01 08 75 a8 90 00 } //1
		$a_03_1 = {b9 ff ff 2f 00 31 c0 83 c0 90 01 01 50 51 6a 00 e8 90 01 04 59 58 e2 f0 90 00 } //1
		$a_01_2 = {8d 43 01 b9 03 00 00 00 99 f7 f9 8b 45 f8 0f b6 04 18 2b c2 d1 f8 79 03 83 d0 00 5a 88 02 43 4e 75 d3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}