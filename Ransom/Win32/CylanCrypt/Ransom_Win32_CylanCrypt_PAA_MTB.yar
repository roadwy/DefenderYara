
rule Ransom_Win32_CylanCrypt_PAA_MTB{
	meta:
		description = "Ransom:Win32/CylanCrypt.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 02 0f b6 80 90 01 04 88 06 0f be 4f fb 0f b6 47 fc 83 e1 03 c1 e8 04 c1 e1 04 0b c8 0f b6 81 90 01 04 88 46 01 0f be 47 fc 0f b6 4f fd 83 e0 0f c1 e0 02 c1 e9 06 0b c8 90 00 } //10
		$a_01_1 = {43 79 6c 61 6e 63 65 20 52 61 6e 73 6f 6d 77 61 72 65 } //1 Cylance Ransomware
		$a_01_2 = {66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //1 files are encrypted
		$a_01_3 = {64 65 63 72 79 70 74 } //1 decrypt
		$a_01_4 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 53 00 68 00 61 00 64 00 6f 00 77 00 43 00 6f 00 70 00 79 00 } //1 SELECT * FROM Win32_ShadowCopy
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}