
rule Virus_Win32_Gael_C{
	meta:
		description = "Virus:Win32/Gael.C,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e8 80 00 00 00 58 ff d0 55 56 57 8b 43 3c 8d 74 03 78 ad ff 36 01 d8 50 8b 48 18 8b 68 20 01 dd e3 5c 49 8b 74 8d 00 01 de 31 ff 31 c0 ac 38 e0 74 07 c1 cf 0d 01 c7 eb f2 39 d7 75 e3 5d 8b 55 24 01 da 66 8b 0c 4a 8b 55 1c 01 da 8b 04 8a 01 d8 59 50 29 e8 39 c8 58 77 27 96 83 ec 40 89 e7 aa ac 3c 2e 75 fa } //1
		$a_01_1 = {68 69 63 75 6d 68 67 61 65 6c 54 } //1 hicumhgaelT
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}