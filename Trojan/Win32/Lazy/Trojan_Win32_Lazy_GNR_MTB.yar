
rule Trojan_Win32_Lazy_GNR_MTB{
	meta:
		description = "Trojan:Win32/Lazy.GNR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {49 44 4c 5f 53 45 51 55 45 4e 43 45 5f 53 65 73 73 69 6f 6e 54 6f 6b 65 6e 4f 52 42 40 40 51 41 45 40 4b 4b 50 41 55 53 65 73 73 69 6f 6e 54 6f 6b 65 6e 4f 52 42 40 40 45 40 5a } //1 IDL_SEQUENCE_SessionTokenORB@@QAE@KKPAUSessionTokenORB@@E@Z
		$a_01_1 = {62 69 6e 64 40 50 72 6f 78 79 46 61 63 74 6f 72 79 40 43 4f 52 42 41 40 40 55 41 45 50 41 58 50 42 44 30 30 30 41 42 56 43 6f 6e 74 65 78 74 40 32 40 41 41 56 45 6e 76 69 72 6f 6e 6d 65 6e 74 40 32 40 40 5a } //1 bind@ProxyFactory@CORBA@@UAEPAXPBD000ABVContext@2@AAVEnvironment@2@@Z
		$a_01_2 = {65 6e 63 6f 64 65 4f 70 40 5f 49 44 4c 5f 53 45 51 55 45 4e 43 45 5f 73 74 72 69 6e 67 40 40 51 42 45 58 41 41 56 52 65 71 75 65 73 74 40 43 4f 52 42 41 40 40 40 5a } //1 encodeOp@_IDL_SEQUENCE_string@@QBEXAAVRequest@CORBA@@@Z
		$a_01_3 = {5f 63 61 73 74 44 6f 77 6e 40 4f 62 6a 65 63 74 40 43 4f 52 42 41 40 40 53 47 50 41 58 50 41 56 31 32 40 50 42 44 41 41 56 45 6e 76 69 72 6f 6e 6d 65 6e 74 40 32 40 40 5a } //1 _castDown@Object@CORBA@@SGPAXPAV12@PBDAAVEnvironment@2@@Z
		$a_01_4 = {47 3a 5c 43 58 52 31 39 5c 42 53 46 5c 69 6e 74 65 6c 5f 61 5c 63 6f 64 65 5c 62 69 6e 5c 50 50 52 44 43 43 43 4f 52 42 41 5f 43 2e 70 64 62 } //1 G:\CXR19\BSF\intel_a\code\bin\PPRDCCCORBA_C.pdb
		$a_80_5 = {50 50 52 44 43 43 43 4f 52 42 41 5f 43 2e 64 6c 6c } //PPRDCCCORBA_C.dll  1
		$a_01_6 = {2e 72 6f 70 66 } //1 .ropf
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_80_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}