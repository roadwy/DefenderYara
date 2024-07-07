
rule Ransom_Win32_BlackCat_A{
	meta:
		description = "Ransom:Win32/BlackCat.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {65 6e 61 62 6c 65 5f 65 73 78 69 5f 76 6d 90 01 01 73 90 00 } //1
		$a_03_1 = {61 75 6c 74 5f 66 69 6c 65 5f 63 69 70 68 90 01 01 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}