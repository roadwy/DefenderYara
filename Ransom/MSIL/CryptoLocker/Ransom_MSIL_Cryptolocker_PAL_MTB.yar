
rule Ransom_MSIL_Cryptolocker_PAL_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {73 75 72 70 72 69 73 65 } //1 surprise
		$a_81_1 = {62 69 6f 72 61 69 6e 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //1 biorain@protonmail.com
		$a_81_2 = {69 6e 66 65 63 74 65 64 20 77 69 74 68 20 61 20 72 61 6e 73 6f 6d 77 61 72 65 } //1 infected with a ransomware
		$a_81_3 = {41 4c 4c 20 4f 46 20 59 4f 55 52 20 46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 } //1 ALL OF YOUR FILES HAVE BEEN ENCRYPTED
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}