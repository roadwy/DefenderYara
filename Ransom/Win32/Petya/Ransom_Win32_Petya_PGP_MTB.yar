
rule Ransom_Win32_Petya_PGP_MTB{
	meta:
		description = "Ransom:Win32/Petya.PGP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {70 65 74 79 61 33 37 68 35 74 62 68 79 76 6b 69 2e 6f 6e 69 6f 6e 2f } //1 petya37h5tbhyvki.onion/
		$a_01_1 = {70 65 74 79 61 35 6b 6f 61 68 74 73 66 37 73 76 2e 6f 6e 69 6f 6e 2f } //4 petya5koahtsf7sv.onion/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*4) >=5
 
}