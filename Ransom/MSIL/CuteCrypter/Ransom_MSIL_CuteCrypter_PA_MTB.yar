
rule Ransom_MSIL_CuteCrypter_PA_MTB{
	meta:
		description = "Ransom:MSIL/CuteCrypter.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 06 00 00 "
		
	strings :
		$a_01_0 = {2e 00 6c 00 6f 00 63 00 6b 00 79 00 } //5 .locky
		$a_01_1 = {2e 00 52 00 65 00 6b 00 65 00 6e 00 53 00 6f 00 6d 00 } //5 .RekenSom
		$a_01_2 = {63 00 75 00 74 00 65 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 } //4 cuteRansomware
		$a_01_3 = {73 00 65 00 6e 00 64 00 42 00 61 00 63 00 6b 00 2e 00 74 00 78 00 74 00 } //1 sendBack.txt
		$a_01_4 = {73 00 65 00 63 00 72 00 65 00 74 00 2e 00 74 00 78 00 74 00 } //1 secret.txt
		$a_01_5 = {73 00 65 00 63 00 72 00 65 00 74 00 41 00 45 00 53 00 2e 00 74 00 78 00 74 00 } //1 secretAES.txt
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*4+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=11
 
}