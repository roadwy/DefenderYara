
rule Trojan_WinNT_Udslee_gen_A{
	meta:
		description = "Trojan:WinNT/Udslee.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 64 5b 64 76 5d 00 } //1
		$a_01_1 = {73 64 72 76 43 6f 6e 66 69 67 00 } //1
		$a_01_2 = {76 62 69 66 75 65 6b 7a 6e 6d 40 67 6a 69 74 6b 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}