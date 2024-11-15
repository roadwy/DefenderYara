
rule Trojan_Win32_Neoreblamy_ASX_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.ASX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 08 00 00 "
		
	strings :
		$a_01_0 = {62 74 50 56 48 75 62 45 65 62 45 51 58 46 75 4f 45 67 4c 73 4e 77 41 73 71 6c 56 78 7a 4f } //1 btPVHubEebEQXFuOEgLsNwAsqlVxzO
		$a_01_1 = {73 6b 65 6a 65 56 51 64 4e 46 78 51 6c 48 7a 4f 45 6b 6b 6f 73 62 57 6d 5a 42 6b 67 6a 4a } //1 skejeVQdNFxQlHzOEkkosbWmZBkgjJ
		$a_01_2 = {46 68 55 6e 43 68 53 4a 7a 73 68 6c 49 72 6b 56 46 4b 62 44 68 73 4c 6f 69 52 41 55 4f 43 51 45 45 58 66 79 58 } //1 FhUnChSJzshlIrkVFKbDhsLoiRAUOCQEEXfyX
		$a_01_3 = {47 4e 63 65 52 68 58 54 57 44 42 6d 44 6b 6f 4a 51 77 76 62 4d 58 4a 65 75 6d 6b 53 59 59 50 56 5a 75 4d 64 6b 56 6d 48 75 } //1 GNceRhXTWDBmDkoJQwvbMXJeumkSYYPVZuMdkVmHu
		$a_01_4 = {79 62 4d 67 6c 45 53 67 6f 6c 58 75 71 59 50 61 56 75 42 67 6f 45 6d 50 52 64 52 57 62 4c } //1 ybMglESgolXuqYPaVuBgoEmPRdRWbL
		$a_01_5 = {48 4f 62 4e 65 56 41 70 4f 68 73 57 72 4c 49 47 4a 42 79 4d 67 65 6d 63 6d 58 67 43 63 72 } //1 HObNeVApOhsWrLIGJByMgemcmXgCcr
		$a_01_6 = {4e 61 42 48 6f 54 43 5a 4d 48 6f 63 68 66 66 6d 46 75 44 45 57 76 64 59 6c 76 67 61 55 6f 78 70 76 73 42 65 67 74 6a 70 49 47 } //1 NaBHoTCZMHochffmFuDEWvdYlvgaUoxpvsBegtjpIG
		$a_01_7 = {51 54 68 4a 6b 65 6d 76 64 6b 55 71 67 67 45 53 4e 56 41 57 4e 6d 67 74 46 4b 6d 6c 58 58 76 51 71 78 4e 66 41 67 55 74 75 61 6b 63 7a 73 47 58 62 67 6d } //1 QThJkemvdkUqggESNVAWNmgtFKmlXXvQqxNfAgUtuakczsGXbgm
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=4
 
}