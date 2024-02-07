
rule Trojan_Win32_Injector_MY_MTB{
	meta:
		description = "Trojan:Win32/Injector.MY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {47 78 6b 65 6f 78 6b 7a 73 } //01 00  Gxkeoxkzs
		$a_81_1 = {50 72 6f 6a 65 63 74 35 31 2e 64 6c 6c } //01 00  Project51.dll
		$a_81_2 = {53 74 67 47 65 74 49 46 69 6c 6c 4c 6f 63 6b 42 79 74 65 73 4f 6e 46 69 6c 65 } //01 00  StgGetIFillLockBytesOnFile
		$a_81_3 = {6c 6f 61 64 70 65 72 66 2e 64 6c 6c } //01 00  loadperf.dll
		$a_81_4 = {49 55 6e 6b 6e 6f 77 6e 5f 41 64 64 52 65 66 5f 50 72 6f 78 79 } //01 00  IUnknown_AddRef_Proxy
		$a_81_5 = {5c 52 65 67 69 73 74 72 79 5c 4d 61 63 68 69 6e 65 5c 53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 4d 70 44 72 69 76 65 72 } //00 00  \Registry\Machine\System\CurrentControlSet\Services\MpDriver
	condition:
		any of ($a_*)
 
}