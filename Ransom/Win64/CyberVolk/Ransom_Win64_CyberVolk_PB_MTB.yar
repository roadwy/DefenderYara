
rule Ransom_Win64_CyberVolk_PB_MTB{
	meta:
		description = "Ransom:Win64/CyberVolk.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 43 79 62 65 72 56 6f 6c 6b } //1 .CyberVolk
		$a_01_1 = {46 49 4c 45 53 20 4c 4f 43 4b 45 44 20 42 59 20 43 59 42 45 52 56 4f 4c 4b } //3 FILES LOCKED BY CYBERVOLK
		$a_01_2 = {59 4f 55 52 20 46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 21 } //1 YOUR FILES HAVE BEEN ENCRYPTED!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1) >=5
 
}