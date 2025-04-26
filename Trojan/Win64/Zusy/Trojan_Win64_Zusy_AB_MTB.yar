
rule Trojan_Win64_Zusy_AB_MTB{
	meta:
		description = "Trojan:Win64/Zusy.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 08 00 00 "
		
	strings :
		$a_01_0 = {41 c6 85 29 01 00 00 00 41 c6 85 28 01 00 00 00 48 8d 8c 24 00 13 00 00 e8 91 69 14 00 48 8d 8c 24 00 13 00 00 e8 77 6c 14 00 a8 01 0f 85 80 2d 00 00 48 89 17 4c 8d 05 b5 57 2c 00 48 8d 8c 24 50 06 00 00 6a 21 41 59 e8 ae 1c ff ff } //2
		$a_00_1 = {63 6f 75 6e 74 72 79 5f 63 6f 64 65 } //1 country_code
		$a_00_2 = {73 74 65 61 6c 65 72 } //1 stealer
		$a_00_3 = {63 61 72 64 5f 6e 75 6d 62 65 72 5f 65 6e 63 72 79 70 74 65 64 } //1 card_number_encrypted
		$a_00_4 = {63 72 65 64 69 74 5f 63 61 72 64 73 } //1 credit_cards
		$a_00_5 = {65 6a 62 61 6c 62 61 6b 6f 70 6c 63 68 6c 67 68 65 63 64 61 6c 6d 65 65 65 61 6a 6e 69 6d 68 6d } //1 ejbalbakoplchlghecdalmeeeajnimhm
		$a_00_6 = {66 68 62 6f 68 69 6d 61 65 6c 62 6f 68 70 6a 62 62 6c 64 63 6e 67 63 6e 61 70 6e 64 6f 64 6a 70 } //1 fhbohimaelbohpjbbldcngcnapndodjp
		$a_01_7 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 } //1 Software\Microsoft\Windows\CurrentVersion\Internet Settings
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_01_7  & 1)*1) >=9
 
}