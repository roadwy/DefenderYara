
rule Trojan_Win32_Gearclop_gen_A{
	meta:
		description = "Trojan:Win32/Gearclop.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {66 ad 86 c4 66 33 05 90 01 04 66 ff 05 90 01 04 66 ab e2 ea 90 00 } //2
		$a_01_1 = {ff e0 8b 3c 24 03 7f 3c 8b f7 8b 7f 34 8b 76 50 } //1
		$a_03_2 = {8b 04 24 03 40 3c 8b 40 28 03 c3 83 c4 90 01 01 ff e0 90 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}