
rule Trojan_Win32_Blister_A{
	meta:
		description = "Trojan:Win32/Blister.A,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_03_0 = {64 a1 30 00 00 00 53 57 89 75 90 01 01 8b 40 0c 8b 40 1c 90 00 } //4
		$a_01_1 = {8b 48 20 8b 50 1c 03 cb 8b 78 24 03 d3 8b 40 18 03 fb } //4
		$a_01_2 = {c1 c2 09 0f be c0 03 d0 41 8a 01 84 c0 } //4
		$a_03_3 = {8b c6 83 e0 03 8a 44 05 90 01 01 30 04 90 01 01 46 81 fe 90 00 } //4
		$a_03_4 = {50 6a ff ff d7 8d 45 90 01 01 50 8d 83 90 01 04 ff d0 90 00 } //4
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_03_3  & 1)*4+(#a_03_4  & 1)*4) >=16
 
}