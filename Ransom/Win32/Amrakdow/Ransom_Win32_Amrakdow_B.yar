
rule Ransom_Win32_Amrakdow_B{
	meta:
		description = "Ransom:Win32/Amrakdow.B,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 00 57 00 39 00 31 00 63 00 69 00 42 00 75 00 5a 00 58 00 52 00 33 00 62 00 33 00 4a 00 72 00 49 00 47 00 68 00 68 00 63 00 79 00 42 00 69 00 5a 00 57 00 56 00 75 00 49 00 47 00 4a 00 79 00 5a 00 57 00 46 00 6a 00 61 00 47 00 56 00 6b 00 49 00 47 00 4a 00 35 00 49 00 45 00 74 00 68 00 63 00 6d 00 31 00 68 00 49 00 48 00 4a 00 68 00 62 00 6e 00 4e 00 76 00 62 00 58 00 64 00 68 00 63 00 6d 00 55 00 67 00 5a 00 } //1 WW91ciBuZXR3b3JrIGhhcyBiZWVuIGJyZWFjaGVkIGJ5IEthcm1hIHJhbnNvbXdhcmUgZ
		$a_01_1 = {61 00 61 00 61 00 5f 00 54 00 6f 00 75 00 63 00 68 00 4d 00 65 00 4e 00 6f 00 74 00 5f 00 2e 00 74 00 78 00 74 00 } //1 aaa_TouchMeNot_.txt
		$a_01_2 = {2d 00 43 00 59 00 50 00 48 00 45 00 52 00 45 00 44 00 44 00 44 00 2e 00 74 00 78 00 74 00 } //1 -CYPHEREDDD.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}