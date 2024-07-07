
rule Ransom_Win32_Spectrypt_A{
	meta:
		description = "Ransom:Win32/Spectrypt.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 48 00 6f 00 77 00 54 00 6f 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 49 00 4d 00 50 00 4f 00 52 00 54 00 41 00 4e 00 54 00 21 00 2e 00 74 00 78 00 74 00 } //1 \Desktop\HowToDecryptIMPORTANT!.txt
		$a_01_1 = {73 68 61 64 6f 77 63 6f 70 79 20 64 65 6c 65 74 65 } //1 shadowcopy delete
		$a_01_2 = {61 30 31 34 32 35 30 33 2e 78 73 70 68 2e 72 75 } //1 a0142503.xsph.ru
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}