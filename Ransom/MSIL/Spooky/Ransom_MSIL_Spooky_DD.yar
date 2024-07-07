
rule Ransom_MSIL_Spooky_DD{
	meta:
		description = "Ransom:MSIL/Spooky.DD,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 73 65 72 73 90 02 10 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 43 72 79 62 6c 65 90 02 05 5c 43 72 79 62 6c 65 90 02 05 5c 6f 62 6a 5c 44 65 62 75 67 5c 43 72 79 62 6c 65 90 02 05 2e 70 64 62 90 00 } //1
		$a_02_1 = {63 72 79 62 6c 65 90 02 05 2e 65 78 65 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}