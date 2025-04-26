
rule Ransom_MSIL_LockbitCrypt_SVA_MTB{
	meta:
		description = "Ransom:MSIL/LockbitCrypt.SVA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 07 11 08 20 00 01 00 00 5d d2 9c 11 08 20 00 01 00 00 5b 13 08 11 07 17 58 13 07 11 07 1a 32 dd } //1
		$a_01_1 = {72 1a 16 00 70 28 17 00 00 0a 0a 72 30 16 00 70 0b 07 72 6e 16 00 70 28 17 00 00 0a 0b 07 72 23 17 00 70 28 17 00 00 0a 0b 07 72 c6 17 00 70 28 17 00 00 0a 0b 07 72 1a 18 00 70 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}