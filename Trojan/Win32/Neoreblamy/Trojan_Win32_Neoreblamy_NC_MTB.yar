
rule Trojan_Win32_Neoreblamy_NC_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_81_0 = {46 4d 75 7a 4f 4c 6b 6a 6a 49 53 57 72 6c 7a 6e 62 47 6b 43 64 75 61 65 5a 64 6f 4b 69 4d 56 59 61 56 } //2 FMuzOLkjjISWrlznbGkCduaeZdoKiMVYaV
		$a_81_1 = {4c 73 6d 4b 46 43 4f 54 42 61 75 61 77 77 57 71 61 64 63 62 56 72 4b 75 79 6e 6f 50 79 63 46 6c 4d 4f 71 } //1 LsmKFCOTBauawwWqadcbVrKuynoPycFlMOq
		$a_81_2 = {73 43 49 4b 53 67 42 59 61 45 59 6b 62 6c 4f 4f 50 64 65 50 74 51 49 71 46 7a 41 7a 4a 41 74 77 4f 48 44 53 48 56 74 4e 4c 4e 4f } //1 sCIKSgBYaEYkblOOPdePtQIqFzAzJAtwOHDSHVtNLNO
		$a_81_3 = {7a 68 49 44 67 57 6f 63 66 48 55 6b 46 71 79 71 77 59 47 55 5a 77 57 57 79 67 71 73 } //1 zhIDgWocfHUkFqyqwYGUZwWWygqs
		$a_81_4 = {41 6b 53 41 70 67 6d 49 65 4d 4c 68 56 42 57 76 75 58 4d 4f 45 68 76 6c 6a 4e 75 6f 6e 49 58 63 4d 4a 49 69 4c 4a 4d 52 4e 59 57 } //1 AkSApgmIeMLhVBWvuXMOEhvljNuonIXcMJIiLJMRNYW
		$a_81_5 = {67 67 76 45 65 62 4e 71 7a 6c 4a 75 5a 41 4d 72 71 54 79 6f 43 66 66 76 66 6b 6f } //1 ggvEebNqzlJuZAMrqTyoCffvfko
		$a_81_6 = {45 67 71 64 4c 6b 41 65 4e 41 4e 6c 6b 51 47 61 74 52 62 4c 4e 74 74 4e 69 59 42 49 } //1 EgqdLkAeNANlkQGatRbLNttNiYBI
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=8
 
}