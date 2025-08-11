
rule Ransom_Win64_Filecoder_YBE_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.YBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 69 6c 65 73 20 48 61 76 65 20 42 65 65 6e 20 45 6e 63 72 79 70 74 65 64 } //1 Files Have Been Encrypted
		$a_01_1 = {65 6e 63 72 79 70 74 65 64 20 62 79 20 6f 75 72 20 61 64 76 61 6e 63 65 64 20 61 74 74 61 63 6b } //1 encrypted by our advanced attack
		$a_01_2 = {48 00 4f 00 57 00 2d 00 54 00 4f 00 2d 00 52 00 45 00 53 00 54 00 4f 00 52 00 45 00 2d 00 59 00 4f 00 55 00 52 00 2d 00 46 00 49 00 4c 00 45 00 53 00 2e 00 74 00 78 00 74 00 } //1 HOW-TO-RESTORE-YOUR-FILES.txt
		$a_01_3 = {6c 00 6f 00 63 00 61 00 74 00 65 00 64 00 20 00 69 00 6e 00 20 00 65 00 76 00 65 00 72 00 79 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 66 00 6f 00 6c 00 64 00 65 00 72 00 } //1 located in every encrypted folder
		$a_00_4 = {42 00 75 00 79 00 20 00 42 00 69 00 74 00 63 00 6f 00 69 00 6e 00 } //1 Buy Bitcoin
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}