
rule Ransom_Win64_Clop_KWAA_MTB{
	meta:
		description = "Ransom:Win64/Clop.KWAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {25 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 4f 00 75 00 74 00 6c 00 6f 00 6f 00 6b 00 } //1 %s\Microsoft\Outlook
		$a_01_1 = {25 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 6f 00 72 00 64 00 } //1 %s\Microsoft\Word
		$a_01_2 = {25 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 4f 00 66 00 66 00 69 00 63 00 65 00 } //1 %s\Microsoft\Office
		$a_01_3 = {4f 00 56 00 45 00 52 00 46 00 49 00 4c 00 45 00 45 00 4e 00 44 00 } //1 OVERFILEEND
		$a_01_4 = {25 00 73 00 5c 00 41 00 41 00 41 00 5f 00 52 00 45 00 41 00 44 00 5f 00 41 00 41 00 41 00 2e 00 54 00 58 00 54 00 } //1 %s\AAA_READ_AAA.TXT
		$a_01_5 = {2e 00 43 00 5f 00 2d 00 5f 00 4c 00 5f 00 2d 00 5f 00 30 00 5f 00 2d 00 5f 00 50 00 } //1 .C_-_L_-_0_-_P
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}