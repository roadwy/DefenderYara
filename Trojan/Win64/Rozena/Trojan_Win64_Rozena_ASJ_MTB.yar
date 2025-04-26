
rule Trojan_Win64_Rozena_ASJ_MTB{
	meta:
		description = "Trojan:Win64/Rozena.ASJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff d5 48 89 c3 49 89 c7 4d 31 c9 49 89 f0 48 89 da 48 89 f9 41 ba 02 d9 c8 5f ff d5 83 f8 00 7d 28 58 41 57 59 68 00 40 00 00 41 58 6a 00 5a 41 ba 0b 2f 0f 30 ff d5 57 59 41 ba 75 6e 4d 61 ff d5 49 ff ce e9 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}