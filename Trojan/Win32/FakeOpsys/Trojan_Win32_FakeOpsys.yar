
rule Trojan_Win32_FakeOpsys{
	meta:
		description = "Trojan:Win32/FakeOpsys,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 02 00 "
		
	strings :
		$a_03_0 = {c6 40 1c 01 a1 90 01 04 e8 90 01 04 8b 45 90 01 01 8b 80 90 01 04 ba 80 ee 36 00 90 00 } //03 00 
		$a_01_1 = {64 65 66 00 ff ff ff ff 03 00 00 00 69 64 69 00 } //02 00 
		$a_01_2 = {0d 62 75 74 74 5f 73 74 6f 70 73 63 61 6e } //01 00  戍瑵彴瑳灯捳湡
		$a_01_3 = {07 51 53 54 69 6d 65 72 } //01 00  儇呓浩牥
		$a_01_4 = {0d 6f 6e 6c 73 65 74 74 69 6e 67 73 5f 75 } //01 00  漍汮敳瑴湩獧畟
		$a_01_5 = {61 70 6c 69 63 61 74 69 6f 6e 20 61 6e 64 20 63 6f 6e 73 75 6c 74 } //01 00  aplication and consult
		$a_01_6 = {4f 70 65 72 61 74 69 6f 6e 20 73 79 73 74 65 6d 20 6b 65 72 6e 65 6c } //00 00  Operation system kernel
	condition:
		any of ($a_*)
 
}