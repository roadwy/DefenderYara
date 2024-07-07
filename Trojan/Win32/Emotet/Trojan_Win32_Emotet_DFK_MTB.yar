
rule Trojan_Win32_Emotet_DFK_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {03 c1 99 8b ce f7 f9 8b 45 f0 83 4d fc ff 8a 4c 15 00 30 08 } //1
		$a_81_1 = {6f 55 70 51 6d 7a 45 4f 39 36 59 6f 77 6b 39 65 62 61 48 39 4d 30 41 72 48 4a 45 63 71 76 57 72 69 } //1 oUpQmzEO96Yowk9ebaH9M0ArHJEcqvWri
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_DFK_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.DFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 d2 8a 94 04 90 01 04 8b c2 03 c1 b9 90 01 04 99 f7 f9 8a 9c 14 90 1b 00 8b 54 24 18 32 1a 90 00 } //1
		$a_81_1 = {36 67 33 74 6d 77 4a 4f 4d 49 55 4e 6f 71 50 73 4a 74 5a 6a 54 34 53 57 70 55 48 32 6f 59 6a 57 30 6d 6f 75 7a 58 6d 31 63 79 70 46 61 } //1 6g3tmwJOMIUNoqPsJtZjT4SWpUH2oYjW0mouzXm1cypFa
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}