
rule Ransom_Win32_Lorenz_MAK_MTB{
	meta:
		description = "Ransom:Win32/Lorenz.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {52 45 47 20 41 44 44 20 22 48 4b 45 59 5f 55 53 45 52 53 5c 90 02 05 5c 43 6f 6e 74 72 6f 6c 20 50 61 6e 65 6c 5c 44 65 73 6b 74 6f 70 22 20 2f 56 20 57 61 6c 6c 70 61 70 65 72 20 2f 54 20 52 45 47 5f 53 5a 20 2f 46 20 2f 44 90 00 } //1
		$a_81_1 = {43 72 79 70 74 45 6e 63 72 79 70 74 } //1 CryptEncrypt
		$a_81_2 = {24 52 65 63 79 63 6c 65 2e 42 69 6e } //1 $Recycle.Bin
		$a_81_3 = {48 45 4c 50 5f 53 45 43 55 52 49 54 59 5f 45 56 45 4e 54 2e 68 74 6d 6c } //1 HELP_SECURITY_EVENT.html
		$a_03_4 = {68 74 74 70 3a 2f 2f 6c 6f 72 65 6e 7a 90 02 35 2e 6f 6e 69 6f 6e 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}