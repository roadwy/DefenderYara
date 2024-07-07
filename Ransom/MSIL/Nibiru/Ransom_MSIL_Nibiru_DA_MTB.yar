
rule Ransom_MSIL_Nibiru_DA_MTB{
	meta:
		description = "Ransom:MSIL/Nibiru.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 70 6f 77 65 72 66 75 6c 20 6d 69 6c 69 74 61 72 79 20 67 72 61 64 65 20 52 61 6e 73 6f 6d 77 61 72 65 } //1 encrypted with powerful military grade Ransomware
		$a_81_1 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //1 @protonmail.com
		$a_81_2 = {2e 4e 69 62 69 72 75 } //1 .Nibiru
		$a_81_3 = {2e 66 75 63 6b 65 64 } //1 .fucked
		$a_81_4 = {59 4f 55 20 48 41 56 45 20 42 45 45 4e 20 48 41 43 4b 45 44 } //1 YOU HAVE BEEN HACKED
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}