
rule Trojan_Win32_Porsmi_gen_A{
	meta:
		description = "Trojan:Win32/Porsmi.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_03_0 = {75 05 89 45 dc eb 59 6a 00 56 8b 4d 0c 51 57 53 ff 15 ?? ?? ?? ?? 85 c0 75 05 89 45 dc eb 41 } //5
		$a_01_1 = {74 63 70 69 70 2e 6c 00 } //3
		$a_01_2 = {70 6f 72 74 61 62 6c 65 6d 73 69 2e 64 6c 6c 00 } //1
		$a_01_3 = {74 63 70 69 70 2e 65 78 65 00 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=9
 
}