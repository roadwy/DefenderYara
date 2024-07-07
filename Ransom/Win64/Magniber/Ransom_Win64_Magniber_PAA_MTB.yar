
rule Ransom_Win64_Magniber_PAA_MTB{
	meta:
		description = "Ransom:Win64/Magniber.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 33 c9 eb 90 0a 05 00 48 33 c9 90 13 32 c0 90 13 8a a6 90 01 04 90 13 32 e0 90 13 80 f4 90 01 01 90 13 88 27 90 13 8a c4 90 13 48 ff c6 90 13 48 ff c7 e9 90 00 } //1
		$a_03_1 = {4c 8b fc eb 90 0a 05 00 4c 8b fc 90 13 48 83 e4 90 01 01 90 13 48 8b ec 90 13 48 83 ec 90 01 01 90 13 48 33 db 90 13 48 c7 c7 90 01 04 90 13 48 89 7d 90 01 01 90 13 48 89 5d 90 01 01 90 13 49 c7 c6 90 01 04 90 13 49 81 f6 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}