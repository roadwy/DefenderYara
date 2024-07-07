
rule Ransom_Win32_Rokku_A{
	meta:
		description = "Ransom:Win32/Rokku.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 6e 63 72 79 70 74 6f 72 2e 64 6c 6c } //1 encryptor.dll
		$a_01_1 = {59 4f 55 52 20 46 49 4c 45 20 48 41 53 20 42 45 45 4e 20 4c 4f 43 4b 45 44 } //1 YOUR FILE HAS BEEN LOCKED
		$a_01_2 = {3a 2f 2f 7a 76 6e 76 70 32 72 68 65 33 6c 6a 77 66 32 6d 2e 6f 6e 69 6f 6e } //2 ://zvnvp2rhe3ljwf2m.onion
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}