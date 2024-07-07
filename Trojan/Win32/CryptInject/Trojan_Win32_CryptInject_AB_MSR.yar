
rule Trojan_Win32_CryptInject_AB_MSR{
	meta:
		description = "Trojan:Win32/CryptInject.AB!MSR,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {64 45 6d 62 35 4d 56 63 6d 47 32 75 42 34 45 77 33 34 6e 78 30 65 6f 58 6a 71 54 6f 51 34 6d 65 53 54 4f 33 61 30 } //1 dEmb5MVcmG2uB4Ew34nx0eoXjqToQ4meSTO3a0
		$a_01_1 = {6b 4d 38 50 6f 41 51 52 41 6f 61 73 48 6a 50 34 4a 4e 6d 4b } //1 kM8PoAQRAoasHjP4JNmK
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}