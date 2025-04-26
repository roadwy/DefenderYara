
rule Ransom_MSIL_Ghyghykrypt_A{
	meta:
		description = "Ransom:MSIL/Ghyghykrypt.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 00 65 00 6e 00 67 00 6f 00 20 00 6d 00 61 00 6c 00 61 00 73 00 20 00 6e 00 6f 00 74 00 69 00 63 00 69 00 61 00 73 00 } //2 Tengo malas noticias
		$a_01_1 = {52 00 45 00 41 00 44 00 5f 00 49 00 54 00 2e 00 74 00 78 00 74 00 } //1 READ_IT.txt
		$a_01_2 = {5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 70 00 61 00 73 00 73 00 2e 00 74 00 78 00 74 00 } //1 \Desktop\pass.txt
		$a_01_3 = {2e 00 74 00 68 00 61 00 74 00 4d 00 6f 00 6d 00 65 00 6e 00 74 00 } //1 .thatMoment
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}