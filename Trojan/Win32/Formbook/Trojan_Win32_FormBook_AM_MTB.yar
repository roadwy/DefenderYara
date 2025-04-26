
rule Trojan_Win32_FormBook_AM_MTB{
	meta:
		description = "Trojan:Win32/FormBook.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc } //3
		$a_01_1 = {89 45 f4 6a 40 68 00 30 00 00 8b 55 f4 52 6a 00 } //3
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3) >=6
 
}
rule Trojan_Win32_FormBook_AM_MTB_2{
	meta:
		description = "Trojan:Win32/FormBook.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 45 fc 33 c5 50 89 65 e8 ff 75 f8 8b 45 fc c7 45 fc fe ff ff ff 89 45 f8 8d 45 f0 } //3
		$a_01_1 = {83 c4 08 89 45 f0 6a 40 68 00 30 00 00 8b 4d f4 } //3
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3) >=6
 
}
rule Trojan_Win32_FormBook_AM_MTB_3{
	meta:
		description = "Trojan:Win32/FormBook.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 00 8b 04 88 2d d6 4b 04 00 41 } //2
		$a_01_1 = {88 04 33 43 81 fb 6c 07 00 00 7c ef } //2
		$a_01_2 = {53 69 6d 70 53 68 61 6e 67 68 61 69 } //2 SimpShanghai
		$a_01_3 = {48 61 72 71 75 65 62 75 73 65 73 } //2 Harquebuses
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}
rule Trojan_Win32_FormBook_AM_MTB_4{
	meta:
		description = "Trojan:Win32/FormBook.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {75 00 69 00 62 00 6d 00 63 00 45 00 4f 00 77 00 51 00 4b 00 4f 00 57 00 72 00 74 00 67 00 31 00 65 00 67 00 45 00 4d 00 74 00 70 00 59 00 4f 00 42 00 41 00 57 00 79 00 46 00 4d 00 77 00 47 00 56 00 65 00 46 00 52 00 4b 00 36 00 35 00 } //1 uibmcEOwQKOWrtg1egEMtpYOBAWyFMwGVeFRK65
		$a_01_1 = {6f 00 6a 00 52 00 74 00 64 00 58 00 50 00 32 00 72 00 50 00 4e 00 46 00 35 00 74 00 6c 00 4f 00 49 00 4b 00 6a 00 54 00 4d 00 52 00 68 00 67 00 35 00 58 00 62 00 63 00 41 00 4c 00 61 00 68 00 6e 00 77 00 4e 00 57 00 59 00 32 00 30 00 36 00 } //1 ojRtdXP2rPNF5tlOIKjTMRhg5XbcALahnwNWY206
		$a_01_2 = {50 00 61 00 59 00 4e 00 75 00 34 00 52 00 7a 00 38 00 74 00 4e 00 79 00 57 00 5a 00 48 00 43 00 47 00 69 00 72 00 49 00 4a 00 6e 00 50 00 58 00 37 00 39 00 55 00 49 00 5a 00 32 00 33 00 34 00 } //1 PaYNu4Rz8tNyWZHCGirIJnPX79UIZ234
		$a_00_3 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //1 MSVBVM60.DLL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule Trojan_Win32_FormBook_AM_MTB_5{
	meta:
		description = "Trojan:Win32/FormBook.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {46 74 70 43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 41 } //1 FtpCreateDirectoryA
		$a_01_1 = {46 74 70 44 65 6c 65 74 65 46 69 6c 65 57 } //1 FtpDeleteFileW
		$a_01_2 = {48 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 57 } //1 HttpSendRequestW
		$a_01_3 = {49 6e 74 65 72 6e 65 74 43 68 65 63 6b 43 6f 6e 6e 65 63 74 69 6f 6e 57 } //1 InternetCheckConnectionW
		$a_01_4 = {52 65 73 55 74 69 6c 47 65 74 41 6c 6c 50 72 6f 70 65 72 74 69 65 73 } //1 ResUtilGetAllProperties
		$a_01_5 = {52 65 73 55 74 69 6c 53 74 6f 70 53 65 72 76 69 63 65 } //1 ResUtilStopService
		$a_01_6 = {43 65 72 74 41 64 64 45 6e 63 6f 64 65 64 43 65 72 74 69 66 69 63 61 74 65 54 6f 53 79 73 74 65 6d 53 74 6f 72 65 57 } //1 CertAddEncodedCertificateToSystemStoreW
		$a_01_7 = {43 65 72 74 44 75 70 6c 69 63 61 74 65 43 65 72 74 69 66 69 63 61 74 65 43 6f 6e 74 65 78 74 } //1 CertDuplicateCertificateContext
		$a_01_8 = {43 72 79 70 74 45 78 70 6f 72 74 50 75 62 6c 69 63 4b 65 79 49 6e 66 6f } //1 CryptExportPublicKeyInfo
		$a_01_9 = {43 72 79 70 74 47 65 74 4f 49 44 46 75 6e 63 74 69 6f 6e 41 64 64 72 65 73 73 } //1 CryptGetOIDFunctionAddress
		$a_01_10 = {43 72 79 70 74 4d 73 67 43 6f 75 6e 74 65 72 73 69 67 6e 45 6e 63 6f 64 65 64 } //1 CryptMsgCountersignEncoded
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}