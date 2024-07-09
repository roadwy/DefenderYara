
rule Trojan_Win32_Jevafus_A{
	meta:
		description = "Trojan:Win32/Jevafus.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {74 03 75 01 90 09 05 00 e8 } //2
		$a_01_1 = {4c 32 68 70 63 47 39 70 62 6e 52 73 64 47 51 75 59 32 39 74 } //1 L2hpcG9pbnRsdGQuY29t
		$a_01_2 = {56 56 4a 4d 66 45 68 6c 59 57 52 73 61 57 35 6c 4b 53 4d 6a 61 48 4a 6c 5a 6a } //1 VVJMfEhlYWRsaW5lKSMjaHJlZj
		$a_01_3 = {4b 47 31 7a 62 6e 78 73 61 58 5a 6c 66 47 31 70 59 33 4a 76 63 32 39 6d 64 43 6d } //1 KG1zbnxsaXZlfG1pY3Jvc29mdCm
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}