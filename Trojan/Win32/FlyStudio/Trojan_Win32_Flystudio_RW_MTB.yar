
rule Trojan_Win32_Flystudio_RW_MTB{
	meta:
		description = "Trojan:Win32/Flystudio.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 0c 00 00 "
		
	strings :
		$a_03_0 = {83 ec 0c 50 ff 74 24 90 01 01 33 c0 89 44 24 90 01 01 89 44 24 90 01 01 89 44 24 90 01 01 8d 54 24 90 01 01 52 ff d3 8b 44 24 90 01 01 8b 54 24 90 01 01 8b 4c 24 90 01 01 83 c4 18 90 00 } //20
		$a_01_1 = {5f 45 4c 5f 48 69 64 65 4f 77 6e 65 72 } //1 _EL_HideOwner
		$a_01_2 = {69 6e 63 6c 75 64 65 20 5c 6c 2e 63 68 73 5c 61 66 78 72 65 73 2e 72 63 } //1 include \l.chs\afxres.rc
		$a_01_3 = {54 24 30 56 52 50 53 51 } //1 T$0VRPSQ
		$a_01_4 = {54 24 54 51 52 50 68 78 } //1 T$TQRPhx
		$a_01_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //1 VirtualAllocEx
		$a_01_6 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_7 = {49 6d 61 67 65 4c 69 73 74 5f 44 65 73 74 72 6f 79 } //1 ImageList_Destroy
		$a_01_8 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
		$a_01_9 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 41 } //1 GetStartupInfoA
		$a_01_10 = {47 65 74 43 50 49 6e 66 6f } //1 GetCPInfo
		$a_01_11 = {5c 45 61 73 79 41 6e 74 69 43 68 65 61 74 5f 78 38 36 2e 64 6c 6c } //1 \EasyAntiCheat_x86.dll
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=30
 
}