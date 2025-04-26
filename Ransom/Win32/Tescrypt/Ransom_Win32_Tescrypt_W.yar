
rule Ransom_Win32_Tescrypt_W{
	meta:
		description = "Ransom:Win32/Tescrypt.W,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 34 01 01 41 3b 4d 0c 76 f6 } //1
		$a_01_1 = {0f b7 c9 c1 c0 07 33 c1 83 c2 02 0f b7 0a 66 85 c9 75 ed } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}