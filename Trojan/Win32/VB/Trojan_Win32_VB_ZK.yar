
rule Trojan_Win32_VB_ZK{
	meta:
		description = "Trojan:Win32/VB.ZK,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {40 00 2a 00 5c 00 41 00 43 00 3a 00 5c 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 20 00 61 00 6e 00 64 00 20 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 43 00 6f 00 6f 00 6c 00 61 00 70 00 70 00 5a 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 63 00 72 00 79 00 70 00 74 00 6f 00 7a 00 5f 00 56 00 33 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //1 @*\AC:\Documents and Settings\CoolappZ\Desktop\cryptoz_V3\Project1.vbp
		$a_00_1 = {5c 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 2e 00 65 00 78 00 65 00 } //1 \crypted.exe
		$a_00_2 = {43 00 61 00 6e 00 20 00 6e 00 6f 00 74 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 76 00 69 00 63 00 74 00 69 00 6d 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 21 00 } //1 Can not start victim process!
		$a_01_3 = {5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //1 ZwUnmapViewOfSection
		$a_01_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_00_5 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 68 00 61 00 63 00 6b 00 69 00 6e 00 67 00 2e 00 67 00 76 00 75 00 2e 00 63 00 63 00 2f 00 } //1 http://hacking.gvu.cc/
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}