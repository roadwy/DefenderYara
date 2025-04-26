
rule Trojan_BAT_DcRat_NZA_MTB{
	meta:
		description = "Trojan:BAT/DcRat.NZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0a 00 00 "
		
	strings :
		$a_81_0 = {55 30 39 47 56 46 64 42 55 6b 56 63 54 57 6c 6a 63 6d 39 7a 62 32 5a 30 58 46 64 70 62 6d 52 76 64 33 4e 63 51 33 56 79 63 6d 56 75 64 46 5a 6c 63 6e 4e 70 62 32 35 63 55 6e 56 75 58 41 3d 3d } //2 U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVuXA==
		$a_81_1 = {4c 32 4d 67 63 32 4e 6f 64 47 46 7a 61 33 4d 67 4c 32 4e 79 5a 57 46 30 5a 53 41 76 5a 69 41 76 63 32 4d 67 62 32 35 73 62 32 64 76 62 69 41 76 63 6d 77 67 61 47 6c 6e 61 47 56 7a 64 43 41 76 64 47 34 67 } //1 L2Mgc2NodGFza3MgL2NyZWF0ZSAvZiAvc2Mgb25sb2dvbiAvcmwgaGlnaGVzdCAvdG4g
		$a_81_2 = {56 6d 6c 79 64 48 56 68 62 46 42 79 62 33 52 6c 59 33 51 3d } //1 VmlydHVhbFByb3RlY3Q=
		$a_81_3 = {51 57 31 7a 61 56 4e 6a 59 57 35 43 64 57 5a 6d 5a 58 49 3d } //1 QW1zaVNjYW5CdWZmZXI=
		$a_81_4 = {44 63 52 61 74 42 79 71 77 71 64 61 6e 63 68 75 6e } //1 DcRatByqwqdanchun
		$a_81_5 = {41 6e 74 69 5f 76 69 72 75 73 } //1 Anti_virus
		$a_81_6 = {50 72 6f 63 65 73 73 48 61 63 6b 65 72 2e 65 78 65 } //1 ProcessHacker.exe
		$a_81_7 = {70 72 6f 63 65 78 70 2e 65 78 65 } //1 procexp.exe
		$a_81_8 = {43 6f 6e 66 69 67 53 65 63 75 72 69 74 79 50 6f 6c 69 63 79 2e 65 78 65 } //1 ConfigSecurityPolicy.exe
		$a_81_9 = {53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 41 6e 74 69 76 69 72 75 73 50 72 6f 64 75 63 74 } //1 Select * from AntivirusProduct
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=11
 
}