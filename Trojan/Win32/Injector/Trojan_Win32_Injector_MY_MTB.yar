
rule Trojan_Win32_Injector_MY_MTB{
	meta:
		description = "Trojan:Win32/Injector.MY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {47 78 6b 65 6f 78 6b 7a 73 } //1 Gxkeoxkzs
		$a_81_1 = {50 72 6f 6a 65 63 74 35 31 2e 64 6c 6c } //1 Project51.dll
		$a_81_2 = {53 74 67 47 65 74 49 46 69 6c 6c 4c 6f 63 6b 42 79 74 65 73 4f 6e 46 69 6c 65 } //1 StgGetIFillLockBytesOnFile
		$a_81_3 = {6c 6f 61 64 70 65 72 66 2e 64 6c 6c } //1 loadperf.dll
		$a_81_4 = {49 55 6e 6b 6e 6f 77 6e 5f 41 64 64 52 65 66 5f 50 72 6f 78 79 } //1 IUnknown_AddRef_Proxy
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}