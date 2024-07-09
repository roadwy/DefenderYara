
rule Trojan_Win32_Simda_gen_B{
	meta:
		description = "Trojan:Win32/Simda.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {80 3e 21 89 74 24 } //2
		$a_03_1 = {76 0b 80 34 30 ?? 83 c0 01 3b c7 72 f5 } //2
		$a_01_2 = {2f 6b 6e 6f 63 6b 2e 70 68 70 3f } //1 /knock.php?
		$a_01_3 = {21 63 6f 6e 66 69 67 } //1 !config
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}