
rule TrojanSpy_Win32_KeyLogger_GC_bit{
	meta:
		description = "TrojanSpy:Win32/KeyLogger.GC!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b c8 8d 34 10 81 e1 3f 00 00 80 79 05 49 83 c9 c0 41 8a 4c 0c 10 8a 1c 37 32 cb 40 3b c5 88 0e 7c de } //2
		$a_01_1 = {47 6c 6f 62 61 6c 5c 47 4c 4f 42 41 4c 5f 53 49 4d 49 43 49 54 53 5f 30 32 33 33 33 33 5f } //1 Global\GLOBAL_SIMICITS_023333_
		$a_01_2 = {00 5c 69 6e 66 6f 2e 64 61 74 00 } //1
		$a_01_3 = {73 6a 69 6f 74 33 30 31 36 2f 66 6b 62 71 28 6d 63 74 } //1 sjiot3016/fkbq(mct
		$a_01_4 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b } //1 Mozilla/4.0 (compatible; MSIE 6.0;
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}