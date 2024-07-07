
rule Ransom_MSIL_ZillaCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/ZillaCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 00 43 00 72 00 79 00 70 00 74 00 } //1 .Crypt
		$a_01_1 = {5c 00 43 00 72 00 79 00 70 00 74 00 5f 00 4d 00 61 00 73 00 73 00 61 00 67 00 65 00 2e 00 74 00 78 00 74 00 } //1 \Crypt_Massage.txt
		$a_01_2 = {44 00 6f 00 6e 00 27 00 74 00 20 00 57 00 6f 00 72 00 72 00 79 00 20 00 46 00 72 00 69 00 65 00 6e 00 64 00 73 00 2c 00 20 00 59 00 6f 00 75 00 20 00 43 00 61 00 6e 00 20 00 52 00 65 00 73 00 74 00 6f 00 72 00 65 00 20 00 41 00 6c 00 6c 00 20 00 59 00 6f 00 75 00 72 00 20 00 46 00 69 00 6c 00 65 00 73 00 21 00 } //1 Don't Worry Friends, You Can Restore All Your Files!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}