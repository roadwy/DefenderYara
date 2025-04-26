
rule Trojan_Win32_Qakbot_DN_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_01_1 = {71 6a 33 32 77 67 37 6c 48 44 53 2e 64 6c 6c } //1 qj32wg7lHDS.dll
		$a_01_2 = {46 72 73 42 5a 44 43 6d 4b } //1 FrsBZDCmK
		$a_01_3 = {53 42 6e 50 4d 57 49 6d } //1 SBnPMWIm
		$a_01_4 = {54 53 4c 78 66 4a 71 } //1 TSLxfJq
		$a_01_5 = {6e 7a 67 43 51 47 52 4c 44 43 } //1 nzgCQGRLDC
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}
rule Trojan_Win32_Qakbot_DN_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.DN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6b 3f 30 41 70 70 65 6e 64 61 62 6c 65 40 69 63 75 5f 35 31 40 40 51 41 45 40 41 42 56 30 31 40 40 5a } //1 k?0Appendable@icu_51@@QAE@ABV01@@Z
		$a_01_1 = {6b 3f 30 42 79 74 65 53 69 6e 6b 40 69 63 75 5f 35 31 40 40 51 41 45 40 58 5a } //1 k?0ByteSink@icu_51@@QAE@XZ
		$a_01_2 = {6b 3f 30 48 61 73 68 74 61 62 6c 65 40 69 63 75 5f 35 31 40 40 51 41 45 40 41 41 57 34 55 45 72 72 6f 72 43 6f 64 65 40 40 40 5a } //1 k?0Hashtable@icu_51@@QAE@AAW4UErrorCode@@@Z
		$a_01_3 = {6b 3f 30 49 44 4e 41 49 6e 66 6f 40 69 63 75 5f 35 31 40 40 51 41 45 40 58 5a } //1 k?0IDNAInfo@icu_51@@QAE@XZ
		$a_01_4 = {6b 3f 30 4d 75 74 65 78 40 69 63 75 5f 35 31 40 40 51 41 45 40 50 41 55 55 4d 75 74 65 78 40 40 40 5a } //1 k?0Mutex@icu_51@@QAE@PAUUMutex@@@Z
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}