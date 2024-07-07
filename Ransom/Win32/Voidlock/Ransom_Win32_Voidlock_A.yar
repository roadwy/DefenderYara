
rule Ransom_Win32_Voidlock_A{
	meta:
		description = "Ransom:Win32/Voidlock.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 6d ff 8a 5e 5e 8a c1 d0 c0 32 c8 d0 c0 32 c8 d0 c0 32 c8 d0 c0 32 46 40 32 c1 32 c5 34 63 } //1
		$a_01_1 = {8a 48 fc 30 08 8a 48 fd 30 48 01 8a 48 fe 30 48 02 8a 48 ff 30 48 03 83 c0 04 4a 75 e3 } //1
		$a_01_2 = {25 00 73 00 2e 00 76 00 65 00 72 00 6e 00 6f 00 73 00 74 00 } //1 %s.vernost
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}