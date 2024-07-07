
rule Ransom_Win32_Loktrom_A{
	meta:
		description = "Ransom:Win32/Loktrom.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 65 62 4d 6f 6e 65 79 } //1 WebMoney
		$a_01_1 = {2f 66 20 2f 69 6d 20 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 /f /im explorer.exe
		$a_01_2 = {b9 a0 00 00 00 ba 98 02 00 00 } //1
		$a_01_3 = {cf f0 e8 eb ee e6 e5 ed e8 e5 ec 20 4d 69 63 72 6f 73 6f 66 74 20 53 65 63 75 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}