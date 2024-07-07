
rule Ransom_MSIL_WanaCryptor_PAA_MTB{
	meta:
		description = "Ransom:MSIL/WanaCryptor.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 73 00 63 00 20 00 6d 00 69 00 6e 00 75 00 74 00 65 00 20 00 2f 00 6d 00 6f 00 20 00 31 00 20 00 2f 00 74 00 6e 00 20 00 50 00 6f 00 6c 00 69 00 63 00 79 00 55 00 70 00 64 00 61 00 74 00 65 00 20 00 2f 00 74 00 72 00 20 00 22 00 } //1 /create /sc minute /mo 1 /tn PolicyUpdate /tr "
		$a_01_1 = {46 00 69 00 6c 00 65 00 73 00 20 00 48 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 21 00 21 00 } //1 Files Have been encrypted!!
		$a_01_2 = {57 61 6e 61 63 72 79 74 6f 72 } //1 Wanacrytor
		$a_01_3 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 } //1 schtasks
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}