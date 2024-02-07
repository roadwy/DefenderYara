
rule Ransom_Win32_GoCrypt_PAB_MTB{
	meta:
		description = "Ransom:Win32/GoCrypt.PAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 6e 63 72 79 70 74 6f 72 } //01 00  encryptor
		$a_01_1 = {21 21 21 20 44 41 4e 47 45 52 20 21 21 21 } //01 00  !!! DANGER !!!
		$a_01_2 = {57 49 4e 4e 45 52 20 57 49 4e 4e 45 52 20 43 48 49 43 4b 45 4e 20 44 49 4e 4e 45 52 } //01 00  WINNER WINNER CHICKEN DINNER
		$a_01_3 = {41 6c 6c 20 79 6f 75 72 20 73 65 72 76 65 72 73 20 61 6e 64 20 63 6f 6d 70 75 74 65 72 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //00 00  All your servers and computers are encrypted
	condition:
		any of ($a_*)
 
}