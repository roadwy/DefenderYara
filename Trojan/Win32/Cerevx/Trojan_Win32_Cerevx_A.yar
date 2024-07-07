
rule Trojan_Win32_Cerevx_A{
	meta:
		description = "Trojan:Win32/Cerevx.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 4d 08 8a 11 8d 41 01 84 d2 74 0e c6 01 00 30 10 8b c8 74 05 41 30 11 75 fb 5d c3 } //1
		$a_02_1 = {5c 6a 61 76 61 25 73 2e 65 78 65 90 02 10 5c 6a 61 76 61 77 25 73 2e 65 78 65 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}