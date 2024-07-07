
rule Trojan_Win32_Broperk_gen_A{
	meta:
		description = "Trojan:Win32/Broperk.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 e8 20 8b df 33 d8 83 c3 20 } //1
		$a_01_1 = {51 7d 79 73 23 76 7f 78 3b 73 6f 7d 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}