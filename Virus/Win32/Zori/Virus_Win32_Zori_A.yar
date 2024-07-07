
rule Virus_Win32_Zori_A{
	meta:
		description = "Virus:Win32/Zori.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 64 69 72 2e 7a 69 70 00 00 00 00 ff ff ff ff 0b 00 00 00 44 6f 77 6e 4c 6f 61 64 44 69 72 00 } //1
		$a_01_1 = {5c 73 76 63 68 6f 73 74 2e 64 6c 6c 00 00 00 00 ff ff ff ff 0c 00 00 00 77 69 6e 6c 6f 67 6f 6e } //1
		$a_01_2 = {b9 a4 d7 f7 d7 e9 a3 ba 20 20 20 20 20 20 20 20 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}