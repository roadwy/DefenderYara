
rule Ransom_Win32_Tescrypt_YAA{
	meta:
		description = "Ransom:Win32/Tescrypt.YAA,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 c5 81 c0 4c 00 00 00 b9 b2 05 00 00 ba 27 af 2b 2e 30 10 40 49 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}