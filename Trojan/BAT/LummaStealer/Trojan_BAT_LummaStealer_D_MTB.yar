
rule Trojan_BAT_LummaStealer_D_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 0a 00 00 "
		
	strings :
		$a_01_0 = {6d 77 54 6a 7a 75 4e 6a 7a 76 61 4f 57 4d 70 68 4a 72 48 78 44 43 43 69 77 73 6b 42 46 } //1 mwTjzuNjzvaOWMphJrHxDCCiwskBF
		$a_01_1 = {41 65 4c 7a 69 4f 52 50 61 7a 68 6d 6a 71 6a 71 56 52 77 55 41 51 45 44 59 42 64 56 56 } //1 AeLziORPazhmjqjqVRwUAQEDYBdVV
		$a_01_2 = {7a 79 64 55 4f 63 68 6b 4a 74 61 55 4d 62 56 64 46 44 6a 79 6b 5a 41 70 6a 66 46 66 6d } //1 zydUOchkJtaUMbVdFDjykZApjfFfm
		$a_01_3 = {62 6f 55 7a 49 57 68 4c 68 4c 44 5a 47 43 4c 42 61 6e 5a 63 46 73 61 66 68 73 64 43 76 } //1 boUzIWhLhLDZGCLBanZcFsafhsdCv
		$a_01_4 = {6b 72 65 62 65 4c 48 78 73 6e 4f 61 68 49 57 7a 68 76 51 6c 4b 59 4b 64 58 79 4d } //1 krebeLHxsnOahIWzhvQlKYKdXyM
		$a_01_5 = {78 46 4d 74 6e 61 7a 64 41 4b 6d 52 77 4e 63 75 72 44 50 46 72 48 55 56 6b 4d 77 50 73 } //1 xFMtnazdAKmRwNcurDPFrHUVkMwPs
		$a_01_6 = {73 78 57 73 42 63 67 4d 53 78 52 64 55 43 4b 58 65 76 66 4a 4b 67 41 47 41 4b 6f 4d 2e 64 6c 6c } //1 sxWsBcgMSxRdUCKXevfJKgAGAKoM.dll
		$a_01_7 = {6e 59 43 58 46 4e 4b 5a 61 52 6e 47 6e 51 6d 79 46 49 48 5a 4e 62 43 78 } //1 nYCXFNKZaRnGnQmyFIHZNbCx
		$a_01_8 = {71 49 61 64 6b 6b 4a 57 53 6c 63 4e 51 64 51 6f 66 68 70 4d 7a 78 72 64 2e 64 6c 6c } //1 qIadkkJWSlcNQdQofhpMzxrd.dll
		$a_01_9 = {4c 73 56 67 48 46 68 41 66 74 68 72 76 72 77 76 56 51 6e 58 56 59 42 53 74 6c 4b 2e 64 6c 6c } //1 LsVgHFhAfthrvrwvVQnXVYBStlK.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=5
 
}