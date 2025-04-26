
rule Ransom_Win32_Babuk_ARA_MTB{
	meta:
		description = "Ransom:Win32/Babuk.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 43 52 59 50 54 50 52 4f 56 2c 20 62 79 65 21 } //2 HCRYPTPROV, bye!
		$a_01_1 = {6b 65 79 73 20 67 65 6e 65 72 61 74 65 64 2e } //2 keys generated.
		$a_01_2 = {2e 74 78 74 20 63 61 6e 27 74 20 62 65 20 62 69 67 67 65 72 20 74 68 61 6e } //2 .txt can't be bigger than
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}