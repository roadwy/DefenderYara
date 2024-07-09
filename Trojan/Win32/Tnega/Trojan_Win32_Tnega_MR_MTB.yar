
rule Trojan_Win32_Tnega_MR_MTB{
	meta:
		description = "Trojan:Win32/Tnega.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c2 03 c8 0f b6 c1 8b 0d [0-04] 0f b6 84 05 [0-04] 30 04 19 43 3b 9d [0-04] 72 90 09 1e 00 0f b6 84 3d [0-04] 88 84 35 [0-04] 88 94 3d [0-04] 0f b6 8c 35 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Tnega_MR_MTB_2{
	meta:
		description = "Trojan:Win32/Tnega.MR!MTB,SIGNATURE_TYPE_PEHSTR,12 00 12 00 0a 00 00 "
		
	strings :
		$a_01_0 = {57 00 49 00 4f 00 53 00 4f 00 53 00 4f 00 53 00 4f 00 57 00 } //10 WIOSOSOSOW
		$a_01_1 = {52 45 53 55 54 49 4c 53 2e 64 6c 6c } //1 RESUTILS.dll
		$a_01_2 = {52 50 43 52 54 34 2e 64 6c 6c } //1 RPCRT4.dll
		$a_01_3 = {77 73 6e 6d 70 33 32 2e 64 6c 6c } //1 wsnmp32.dll
		$a_01_4 = {5f 6b 62 68 69 74 } //1 _kbhit
		$a_01_5 = {43 00 4f 00 4e 00 49 00 4e 00 24 00 } //1 CONIN$
		$a_01_6 = {52 65 73 55 74 69 6c 53 74 6f 70 52 65 73 6f 75 72 63 65 53 65 72 76 69 63 65 } //1 ResUtilStopResourceService
		$a_01_7 = {4e 64 72 43 6f 6e 66 6f 72 6d 61 6e 74 56 61 72 79 69 6e 67 41 72 72 61 79 4d 61 72 73 68 61 6c 6c } //1 NdrConformantVaryingArrayMarshall
		$a_01_8 = {57 53 41 4c 6f 6f 6b 75 70 53 65 72 76 69 63 65 42 65 67 69 6e 57 } //1 WSALookupServiceBeginW
		$a_01_9 = {45 6d 70 74 79 43 6c 69 70 62 6f 61 72 64 } //1 EmptyClipboard
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=18
 
}