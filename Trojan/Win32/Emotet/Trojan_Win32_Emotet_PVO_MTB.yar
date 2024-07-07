
rule Trojan_Win32_Emotet_PVO_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PVO!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {78 45 6c 35 66 52 41 79 56 75 4c 46 62 4f 33 67 4a 30 37 58 6e 49 6e 32 6b 47 6e 76 59 68 33 33 69 36 } //1 xEl5fRAyVuLFbO3gJ07XnIn2kGnvYh33i6
		$a_01_1 = {41 5a 6a 4a 71 52 38 72 77 69 68 69 69 76 69 36 73 69 4d 57 4a 42 4f 4c 4e 74 36 45 65 51 6e 4b 51 53 72 74 6d 4a 50 32 4c 32 4c 5a 34 70 57 4c 63 61 53 66 67 70 4d 4c 44 39 68 47 45 50 62 79 } //1 AZjJqR8rwihiivi6siMWJBOLNt6EeQnKQSrtmJP2L2LZ4pWLcaSfgpMLD9hGEPby
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}