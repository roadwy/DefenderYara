
rule Trojan_Win32_Wisp_gen_B{
	meta:
		description = "Trojan:Win32/Wisp.gen!B,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 61 69 6c 75 65 72 20 2e 2e 2e 20 41 63 63 65 73 73 20 69 73 20 44 65 6e 69 65 64 20 21 0a 00 } //1
		$a_01_1 = {53 74 6f 70 70 69 6e 67 20 53 65 72 76 69 63 65 20 2e 2e 2e 2e 20 00 00 6e 6f 20 45 78 69 73 74 73 20 21 0a 00 } //1
		$a_01_2 = {2a 2e 2a 00 25 2d 33 30 73 2d 3e 25 2d 64 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}