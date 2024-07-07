
rule Trojan_Win32_Powemet{
	meta:
		description = "Trojan:Win32/Powemet,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5b 43 6f 6e 76 65 72 74 5d 3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 48 34 73 49 41 4f 53 48 4d 31 6f 43 41 37 56 57 62 57 2f 61 53 42 44 2b 6e 45 72 39 44 31 61 46 68 4b 30 51 62 46 4a 4b 61 4b 52 49 74 7a 59 6d 6d 4f 49 45 78 32 44 65 69 6b 36 4f 76 64 67 62 72 31 2f 4f 4c 77 47 6e 31 2f 39 2b 59 38 41 4a 61 5a 4a 54 71 74 4e 5a 53 } //1 [Convert]::FromBase64String('H4sIAOSHM1oCA7VWbW/aSBD+nEr9D1aFhK0QbFJKaKRItzYmmOIEx2Deik6Ovdgbr1/OLwGn1/9+Y8AJaZJTqtNZS
		$a_01_1 = {31 69 39 70 65 47 76 53 2f 62 5a 63 4d 69 30 58 4d 79 63 6f 73 41 76 5a 49 4c 54 4d 41 6c 56 64 6a 79 68 4a 32 65 72 33 37 31 56 75 63 64 4a 59 31 75 57 2f 4d 70 4d 6d 62 46 58 50 6b 78 54 37 64 5a 76 53 4b 73 66 38 35 41 71 48 6f 7a 7a 43 62 46 55 6c 56 68 77 6d 34 53 71 74 54 30 } //1 1i9peGvS/bZcMi0XMycosAvZILTMAlVdjyhJ2er371VucdJY1uW/MpMmbFXPkxT7dZvSKsf85AqHozzCbFUlVhwm4SqtT0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}