
rule Trojan_Win32_SpectreRat_ASP_MTB{
	meta:
		description = "Trojan:Win32/SpectreRat.ASP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {42 33 43 38 33 30 43 41 2d 34 34 33 33 2d 43 43 33 41 2d 36 37 33 37 } //1 B3C830CA-4433-CC3A-6737
		$a_01_1 = {43 75 6c 6c 69 6e 65 74 50 72 6f 67 72 61 6d } //2 CullinetProgram
		$a_01_2 = {6d 61 6e 6a 69 74 61 75 67 75 73 74 75 73 77 61 74 65 72 73 2e 63 6f 6d } //3 manjitaugustuswaters.com
		$a_01_3 = {37 36 45 38 39 34 30 30 35 63 32 44 45 38 36 45 34 30 62 30 33 32 61 30 39 33 31 44 32 41 42 43 30 35 43 36 65 42 33 36 41 43 62 31 43 31 38 46 35 62 36 34 30 61 44 32 34 42 62 63 39 34 35 34 } //4 76E894005c2DE86E40b032a0931D2ABC05C6eB36ACb1C18F5b640aD24Bbc9454
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*4) >=10
 
}