
rule Ransom_MSIL_Cryptolocker_PAM_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 72 61 7a 79 } //1 Crazy
		$a_01_1 = {57 00 61 00 72 00 6e 00 69 00 6e 00 67 00 2e 00 74 00 78 00 74 00 } //1 Warning.txt
		$a_01_2 = {46 00 69 00 6c 00 65 00 20 00 69 00 73 00 20 00 61 00 6c 00 72 00 65 00 61 00 64 00 79 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 2e 00 } //1 File is already encrypted.
		$a_01_3 = {41 00 6c 00 6c 00 20 00 6f 00 66 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 21 00 } //1 All of your files have been encrypted!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}