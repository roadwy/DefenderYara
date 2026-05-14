
rule Ransom_Win64_Milkyway_YBG_MTB{
	meta:
		description = "Ransom:Win64/Milkyway.YBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 6c 6f 63 6b 2e 70 6e 67 } //1 C:\Windows\lock.png
		$a_01_1 = {49 4e 43 4f 52 52 45 43 54 20 44 45 43 52 59 50 54 49 4f 4e 20 4b 45 59 } //1 INCORRECT DECRYPTION KEY
		$a_01_2 = {52 45 41 44 4d 45 2e 74 78 74 } //1 README.txt
		$a_01_3 = {4d 69 6c 6b 79 77 61 79 4d 75 74 65 78 } //1 MilkywayMutex
		$a_01_4 = {65 6e 63 72 79 70 74 65 64 20 79 6f 75 72 20 69 6e 66 72 61 73 74 72 75 63 74 75 72 65 } //1 encrypted your infrastructure
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}