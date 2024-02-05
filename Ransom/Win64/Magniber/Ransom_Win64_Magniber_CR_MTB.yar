
rule Ransom_Win64_Magniber_CR_MTB{
	meta:
		description = "Ransom:Win64/Magniber.CR!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 ff c1 e9 50 ff ff ff 7a 5e 6f 0d 9b 8e 3e b7 2e 13 99 a2 c8 a2 da 45 86 5e eb 94 43 1a 5b 18 c8 1e 65 b3 5d df f7 db 56 8a d0 e9 40 ff ff ff 2f 36 90 06 e6 eb 05 bf 73 af 37 04 48 ff c6 e9 f8 fe ff ff d5 56 2c 56 a2 5e 21 ca 65 ed c6 d2 8a 86 ed 02 00 00 eb 15 ca d6 27 60 91 b5 0c 69 2a c7 dc 92 2c c4 f3 59 e9 49 fd ff ff 32 86 c0 02 00 00 e9 1f ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}