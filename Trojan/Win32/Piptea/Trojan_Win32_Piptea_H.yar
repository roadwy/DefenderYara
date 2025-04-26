
rule Trojan_Win32_Piptea_H{
	meta:
		description = "Trojan:Win32/Piptea.H,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_03_0 = {58 83 c0 01 90 17 03 02 02 02 8b 4d 89 45 ff 75 90 09 07 00 ff 75 } //3
		$a_01_1 = {c1 e8 10 c1 e0 10 5d } //3
		$a_01_2 = {ff 75 f4 58 83 c0 04 89 45 f4 e9 } //3
		$a_03_3 = {81 bd 64 f7 ff ff 00 00 20 00 73 ?? e8 } //3
		$a_01_4 = {ff 72 34 58 89 45 } //1
		$a_01_5 = {8b 42 34 89 45 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_03_3  & 1)*3+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}