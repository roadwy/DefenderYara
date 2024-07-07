
rule Trojan_Win32_DCPter_gen_A{
	meta:
		description = "Trojan:Win32/DCPter.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 68 79 73 69 63 61 6c 44 72 69 76 65 58 00 00 53 4f 46 54 } //1
		$a_01_1 = {5c 53 59 53 54 45 4d 33 32 5c 44 52 49 56 45 52 53 5c 00 00 5c 3f 3f 5c } //1
		$a_01_2 = {53 61 74 79 61 6d 65 76 61 20 4a 61 79 61 74 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}