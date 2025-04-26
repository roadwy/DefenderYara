
rule Trojan_AndroidOS_Starwarz_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Starwarz.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {34 41 34 45 6c 35 77 45 46 33 73 4f 6a 66 31 77 6d 41 56 7a 57 4a 56 61 52 70 4d 56 4c 32 62 67 56 71 48 79 74 76 31 57 62 67 } //2 4A4El5wEF3sOjf1wmAVzWJVaRpMVL2bgVqHytv1Wbg
		$a_00_1 = {3a 2f 2f 6d 6f 6e 74 61 6e 61 74 6f 6e 79 2e 78 79 7a 2f 61 70 69 2f } //1 ://montanatony.xyz/api/
		$a_00_2 = {64 6f 49 6e 42 61 63 6b 67 72 6f 75 6e 64 } //1 doInBackground
		$a_00_3 = {61 63 68 69 6c 6c 69 65 73 2f 32 46 41 2e 70 68 70 } //1 achillies/2FA.php
		$a_00_4 = {46 55 43 4b 49 4e 47 20 43 55 4e 54 20 2c 20 41 52 45 20 59 4f 55 20 44 45 43 4f 4d 50 49 4c 49 4e 47 20 48 55 48 3f } //1 FUCKING CUNT , ARE YOU DECOMPILING HUH?
		$a_00_5 = {53 78 51 32 48 32 7a 6c 2b 70 48 78 59 38 4d 5a 46 34 56 59 33 51 } //2 SxQ2H2zl+pHxY8MZF4VY3Q
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*2) >=4
 
}