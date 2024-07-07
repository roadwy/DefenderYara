
rule Trojan_Win32_Tondirt_A{
	meta:
		description = "Trojan:Win32/Tondirt.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 2e 65 78 65 20 2f 43 20 72 65 6d 6f 76 65 72 2e 62 61 74 00 } //1
		$a_01_1 = {00 4e 6f 20 41 56 20 64 65 74 65 63 74 65 64 00 } //1
		$a_01_2 = {00 70 25 30 35 64 2e 70 6c 67 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}