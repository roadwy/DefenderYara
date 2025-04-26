
rule Ransom_Win64_Rancoz_MA_MTB{
	meta:
		description = "Ransom:Win64/Rancoz.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {52 65 61 64 20 48 4f 57 5f 54 4f 5f 52 45 43 4f 56 45 52 59 5f 46 49 4c 45 53 } //1 Read HOW_TO_RECOVERY_FILES
		$a_01_1 = {48 65 6c 6c 6f 21 20 59 6f 75 72 20 63 6f 6d 70 61 6e 79 20 68 61 73 20 62 65 65 6e 20 68 61 63 6b 65 64 21 } //1 Hello! Your company has been hacked!
		$a_01_2 = {59 6f 75 72 20 64 61 74 61 20 61 72 65 20 73 74 6f 6c 65 6e 20 61 6e 64 20 65 6e 63 72 79 70 74 65 64 } //1 Your data are stolen and encrypted
		$a_01_3 = {57 65 20 61 72 65 20 6e 6f 74 20 61 20 70 6f 6c 69 74 69 63 61 6c 6c 79 20 6d 6f 74 69 76 61 74 65 64 20 67 72 6f 75 70 20 61 6e 64 20 77 65 20 64 6f 20 6e 6f 74 20 6e 65 65 64 20 61 6e 79 74 68 69 6e 67 20 6f 74 68 65 72 20 74 68 61 6e 20 79 6f 75 72 20 6d 6f 6e 65 79 2e 20 } //1 We are not a politically motivated group and we do not need anything other than your money. 
		$a_01_4 = {4c 69 66 65 20 69 73 20 74 6f 6f 20 73 68 6f 72 74 20 74 6f 20 62 65 20 73 61 64 2e 20 42 65 20 6e 6f 74 20 73 61 64 2c 20 6d 6f 6e 65 79 2c 20 69 74 20 69 73 20 6f 6e 6c 79 20 70 61 70 65 72 2e } //1 Life is too short to be sad. Be not sad, money, it is only paper.
		$a_01_5 = {57 61 72 6e 69 6e 67 21 20 49 66 20 79 6f 75 20 64 6f 20 6e 6f 74 20 70 61 79 20 74 68 65 20 72 61 6e 73 6f 6d 20 77 65 20 77 69 6c 6c 20 61 74 74 61 63 6b 20 79 6f 75 72 20 63 6f 6d 70 61 6e 79 20 72 65 70 65 61 74 65 64 6c 79 20 61 67 61 69 6e } //1 Warning! If you do not pay the ransom we will attack your company repeatedly again
		$a_01_6 = {48 4f 57 5f 54 4f 5f 52 45 43 4f 56 45 52 59 5f 46 49 4c 45 53 2e 74 78 74 } //1 HOW_TO_RECOVERY_FILES.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}