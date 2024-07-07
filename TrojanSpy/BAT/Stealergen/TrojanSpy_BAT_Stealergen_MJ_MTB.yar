
rule TrojanSpy_BAT_Stealergen_MJ_MTB{
	meta:
		description = "TrojanSpy:BAT/Stealergen.MJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {24 24 6d 65 74 68 6f 64 30 78 36 30 30 30 30 32 38 2d 31 30 30 } //1 $$method0x6000028-100
		$a_01_1 = {24 24 6d 65 74 68 6f 64 30 78 36 30 30 30 30 32 61 2d 31 30 30 } //1 $$method0x600002a-100
		$a_01_2 = {24 24 6d 65 74 68 6f 64 30 78 36 30 30 30 30 32 38 2d 32 33 36 } //1 $$method0x6000028-236
		$a_01_3 = {59 00 61 00 6e 00 64 00 65 00 78 00 } //1 Yandex
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_5 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_6 = {67 65 74 5f 43 75 72 72 65 6e 74 54 68 72 65 61 64 } //1 get_CurrentThread
		$a_01_7 = {49 73 4c 6f 67 67 69 6e 67 } //1 IsLogging
		$a_01_8 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_9 = {44 65 62 75 67 67 65 72 } //1 Debugger
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}