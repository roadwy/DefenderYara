
rule Trojan_Win32_Vaklik_C{
	meta:
		description = "Trojan:Win32/Vaklik.C,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {3a 4c ff 0a 00 4e 38 ff 04 38 ff 04 28 ff 0a 0b 00 08 00 04 28 ff 3a 18 ff 0c 00 fb ef f8 fe 60 23 6c ff f4 01 f4 ff } //1
		$a_01_1 = {45 56 45 4e 54 5f 53 49 4e 4b 5f 41 64 64 52 65 66 } //1 EVENT_SINK_AddRef
		$a_01_2 = {45 56 45 4e 54 5f 53 49 4e 4b 5f 52 65 6c 65 61 73 65 } //1 EVENT_SINK_Release
		$a_01_3 = {45 56 45 4e 54 5f 53 49 4e 4b 5f 51 75 65 72 79 49 6e 74 65 72 66 61 63 65 } //1 EVENT_SINK_QueryInterface
		$a_01_4 = {73 00 74 00 75 00 62 00 2e 00 76 00 62 00 70 00 } //1 stub.vbp
		$a_01_5 = {74 00 6d 00 70 00 2e 00 65 00 78 00 65 00 } //1 tmp.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}