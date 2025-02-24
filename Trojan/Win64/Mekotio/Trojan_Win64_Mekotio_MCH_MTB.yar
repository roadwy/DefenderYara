
rule Trojan_Win64_Mekotio_MCH_MTB{
	meta:
		description = "Trojan:Win64/Mekotio.MCH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {55 56 77 38 59 43 6d 5a 39 76 6e 74 46 39 42 74 35 47 68 48 2f 2d 72 54 36 6a 42 43 4f 41 58 65 63 68 35 48 35 4f 69 75 57 } //1 UVw8YCmZ9vntF9Bt5GhH/-rT6jBCOAXech5H5OiuW
		$a_81_1 = {49 6e 6a 65 63 74 6d 6f 64 75 6c 65 63 6f 6e 73 65 69 74 6f } //1 Injectmoduleconseito
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}