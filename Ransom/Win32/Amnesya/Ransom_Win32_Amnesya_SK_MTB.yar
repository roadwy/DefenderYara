
rule Ransom_Win32_Amnesya_SK_MTB{
	meta:
		description = "Ransom:Win32/Amnesya.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 48 45 20 46 49 4c 45 20 49 53 20 45 4e 43 52 59 50 54 45 44 20 57 49 54 48 20 54 48 45 20 52 53 41 2d 32 30 34 38 20 41 4c 47 4f 52 49 54 48 4d 2c 20 4f 4e 4c 59 20 57 45 20 43 41 4e 20 44 45 43 52 59 50 54 20 54 48 45 20 46 49 4c 45 } //1 THE FILE IS ENCRYPTED WITH THE RSA-2048 ALGORITHM, ONLY WE CAN DECRYPT THE FILE
		$a_01_1 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 21 } //1 Your files are encrypted!
		$a_01_2 = {49 46 20 59 4f 55 20 44 4f 20 4e 4f 54 20 48 41 56 45 20 41 20 4a 41 42 42 45 52 2e 20 54 4f 20 57 52 49 54 45 20 54 4f 20 55 53 20 54 4f 20 52 45 47 49 53 54 45 52 } //1 IF YOU DO NOT HAVE A JABBER. TO WRITE TO US TO REGISTER
		$a_01_3 = {73 79 73 74 65 6d 33 32 2e 65 78 65 } //5 system32.exe
		$a_01_4 = {5b 2f 54 41 53 4b 4e 41 4d 45 5d 5b 41 55 54 4f 45 58 45 43 5d 5b 52 45 41 44 4d 45 5d 48 4f 57 20 54 4f 20 52 45 43 4f 56 45 } //5 [/TASKNAME][AUTOEXEC][README]HOW TO RECOVE
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5) >=12
 
}