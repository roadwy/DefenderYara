
rule Ransom_Win64_Encoder_PF_MTB{
	meta:
		description = "Ransom:Win64/Encoder.PF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {42 4f 54 5f 43 4f 4e 4e 45 43 54 45 44 } //1 BOT_CONNECTED
		$a_01_1 = {5c 00 52 00 45 00 41 00 44 00 5f 00 4d 00 45 00 2e 00 74 00 78 00 74 00 } //1 \READ_ME.txt
		$a_01_2 = {59 4f 55 52 20 46 49 4c 45 53 20 41 52 45 20 45 4e 43 52 59 50 54 45 44 } //3 YOUR FILES ARE ENCRYPTED
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3) >=5
 
}
rule Ransom_Win64_Encoder_PF_MTB_2{
	meta:
		description = "Ransom:Win64/Encoder.PF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {23 23 23 20 54 48 33 20 47 52 33 33 4e 20 42 4c 30 30 44 20 47 52 30 55 50 20 20 23 23 23 } //3 ### TH3 GR33N BL00D GR0UP  ###
		$a_01_1 = {41 4c 4c 20 59 4f 55 52 20 46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 21 } //1 ALL YOUR FILES HAVE BEEN ENCRYPTED!
		$a_03_2 = {46 69 6c 65 73 20 65 6e 63 72 79 70 74 65 64 3a 20 [0-10] 20 65 78 74 65 6e 73 69 6f 6e } //1
		$a_01_3 = {59 4f 55 52 20 44 41 54 41 20 49 53 20 4e 4f 57 20 48 45 4c 44 20 46 4f 52 20 52 41 4e 53 4f 4d } //1 YOUR DATA IS NOW HELD FOR RANSOM
		$a_01_4 = {79 6f 75 72 20 6e 65 74 77 6f 72 6b 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 61 6e 64 20 70 65 6e 65 74 72 61 74 65 64 20 62 79 20 54 48 45 2d 47 52 45 45 4e 2d 42 4c 4f 4f 44 2d 47 52 4f 55 50 } //1 your network have been encrypted and penetrated by THE-GREEN-BLOOD-GROUP
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}