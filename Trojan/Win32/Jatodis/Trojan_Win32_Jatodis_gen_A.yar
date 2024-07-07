
rule Trojan_Win32_Jatodis_gen_A{
	meta:
		description = "Trojan:Win32/Jatodis.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 73 3c 03 f3 ff 15 } //1
		$a_03_1 = {0f be 3f 0f be 00 33 f8 8d 4d 90 01 01 57 53 ff 15 90 00 } //1
		$a_01_2 = {2f 6a 73 2f 64 61 74 61 2f } //1 /js/data/
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}