
rule Trojan_Win32_Scrop_BM_MSR{
	meta:
		description = "Trojan:Win32/Scrop.BM!MSR,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 55 49 44 2e 62 69 6e } //1 GUID.bin
		$a_01_1 = {50 73 74 43 4d 44 5f 53 43 } //1 PstCMD_SC
		$a_01_2 = {6a 75 64 79 73 74 65 76 65 6e 73 6f 6e 2e 69 6e 66 6f 2f 76 63 61 70 69 63 76 2f 76 63 68 69 76 6d 71 65 63 76 } //1 judystevenson.info/vcapicv/vchivmqecv
		$a_01_3 = {77 69 6e 6d 67 6d 74 73 3a 5c 5c 6c 6f 63 61 6c 68 6f 73 74 5c 72 6f 6f 74 5c 53 65 63 75 72 69 74 79 43 65 6e 74 65 72 32 } //1 winmgmts:\\localhost\root\SecurityCenter2
		$a_01_4 = {4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 53 65 63 50 72 6f 63 65 73 73 69 6e 67 57 69 6e 64 6f 77 73 53 79 73 74 65 6d 2e 6c 6e 6b } //1 Microsoft\Windows\Start Menu\Programs\Startup\SecProcessingWindowsSystem.lnk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}