
rule Ransom_Win32_Crypmodng_PGU_MTB{
	meta:
		description = "Ransom:Win32/Crypmodng.PGU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {65 6e 63 72 79 70 74 20 66 69 6c 65 20 3a } //1 encrypt file :
		$a_01_1 = {65 6e 63 72 79 70 74 20 66 69 6c 65 20 63 6f 75 6e 74 20 3a } //1 encrypt file count :
		$a_01_2 = {58 35 4f 21 50 25 40 41 50 5b 34 5c 50 5a 58 35 34 28 50 5e 29 37 43 43 29 37 7d 24 45 49 43 41 52 2d 53 54 41 4e 44 41 52 44 2d 41 4e 54 49 56 49 52 55 53 2d 54 45 53 54 2d 46 49 4c 45 21 24 48 2b 48 2a } //1 X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
		$a_01_3 = {24 00 00 00 00 00 00 00 b0 cf 7a 31 f4 ae 14 62 f4 ae 14 62 f4 ae 14 62 fd d6 87 62 f8 ae 14 62 55 d9 10 63 f8 ae 14 62 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}