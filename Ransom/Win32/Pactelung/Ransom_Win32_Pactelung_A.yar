
rule Ransom_Win32_Pactelung_A{
	meta:
		description = "Ransom:Win32/Pactelung.A,SIGNATURE_TYPE_PEHSTR,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 00 4c 00 45 00 52 00 54 00 3a 00 20 00 50 00 4c 00 45 00 41 00 53 00 45 00 20 00 44 00 4f 00 20 00 4e 00 4f 00 54 00 20 00 53 00 48 00 55 00 54 00 44 00 4f 00 57 00 4e 00 20 00 43 00 4f 00 4d 00 50 00 55 00 54 00 45 00 52 00 } //10 ALERT: PLEASE DO NOT SHUTDOWN COMPUTER
		$a_01_1 = {2e 6f 6e 69 6f 6e } //1 .onion
		$a_01_2 = {70 00 61 00 74 00 63 00 68 00 65 00 28 00 73 00 29 00 } //1 patche(s)
		$a_01_3 = {26 26 20 65 78 69 74 } //1 && exit
		$a_01_4 = {2f 69 6e 64 65 78 2e 70 68 70 } //1 /index.php
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}