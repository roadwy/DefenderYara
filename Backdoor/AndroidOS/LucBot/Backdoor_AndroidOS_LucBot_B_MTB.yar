
rule Backdoor_AndroidOS_LucBot_B_MTB{
	meta:
		description = "Backdoor:AndroidOS/LucBot.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {44 45 43 52 59 50 54 45 44 20 41 4e 44 20 44 45 4c 45 54 45 44 20 41 50 50 20 46 52 4f 4d 20 50 48 4f 4e 45 } //1 DECRYPTED AND DELETED APP FROM PHONE
		$a_00_1 = {2e 4c 75 63 79 } //1 .Lucy
		$a_00_2 = {2f 70 72 69 76 61 74 65 2f 61 64 64 5f 6c 6f 67 2e 70 68 70 } //1 /private/add_log.php
		$a_00_3 = {68 74 74 70 2f 70 72 69 76 61 74 65 2f 72 65 67 2e 70 68 70 } //1 http/private/reg.php
		$a_00_4 = {6c 61 73 74 20 70 61 79 6d 65 6e 74 20 6d 65 74 68 6f 64 20 77 61 73 20 64 65 63 6c 69 6e 65 64 } //1 last payment method was declined
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}