
rule Trojan_Win32_Alureon_CU{
	meta:
		description = "Trojan:Win32/Alureon.CU,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {eb 7f 8d 45 e4 50 6a 00 6a 01 53 ff 15 90 00 } //1
		$a_01_1 = {50 6a 5a 53 ff d7 8d 45 } //1
		$a_01_2 = {67 61 73 66 6b 79 } //1 gasfky
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}