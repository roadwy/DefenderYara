
rule Ransom_MSIL_BlackClaw_DEA_MTB{
	meta:
		description = "Ransom:MSIL/BlackClaw.DEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {52 45 43 4f 56 45 52 20 59 4f 55 52 20 46 49 4c 45 53 2e 68 74 61 } //1 RECOVER YOUR FILES.hta
		$a_81_1 = {52 45 43 4f 56 45 52 20 59 4f 55 52 20 46 49 4c 45 53 2e 74 78 74 } //1 RECOVER YOUR FILES.txt
		$a_81_2 = {2e 5b 7b 30 7d 5d 2e 62 63 6c 61 77 } //1 .[{0}].bclaw
		$a_81_3 = {2e 62 63 6c 61 77 } //1 .bclaw
		$a_81_4 = {68 74 74 70 73 3a 2f 2f 63 6c 61 77 2e 62 6c 61 63 6b 2f } //1 https://claw.black/
		$a_81_5 = {2f 43 20 63 68 6f 69 63 65 20 2f 43 20 59 20 2f 4e 20 2f 44 20 59 20 2f 54 20 33 20 26 20 44 65 6c 20 22 } //1 /C choice /C Y /N /D Y /T 3 & Del "
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}