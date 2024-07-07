
rule Virus_Win32_Chiton_gen_A{
	meta:
		description = "Virus:Win32/Chiton.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 81 3f 4d 5a 75 0b 8b 77 3c 03 f7 ad 05 b0 ba ff ff c3 } //1
		$a_01_1 = {68 72 75 67 3e 68 20 3c 53 68 68 72 67 62 21 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}