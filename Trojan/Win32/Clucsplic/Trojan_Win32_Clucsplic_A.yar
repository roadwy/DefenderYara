
rule Trojan_Win32_Clucsplic_A{
	meta:
		description = "Trojan:Win32/Clucsplic.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {4e 74 43 72 65 61 74 65 54 68 72 65 61 64 00 00 57 61 72 6e 69 6e 67 3a 20 43 6f 6d 70 6f 6e 65 } //5
		$a_01_1 = {5c 5c 2e 5c 47 6c 6f 62 61 6c } //1 \\.\Global
		$a_01_2 = {8d 45 e4 50 8d 4d fc 51 6a 00 6a 00 6a 0c 8d 55 d8 52 68 00 e0 22 00 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*5) >=6
 
}