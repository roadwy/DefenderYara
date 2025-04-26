
rule Trojan_Win32_Shelma_NS_MTB{
	meta:
		description = "Trojan:Win32/Shelma.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 4d e8 64 a3 00 00 00 00 8b 1e 6a 18 e8 ?? ?? ?? ?? 83 c4 04 8d 78 10 8b 4d 0c f2 0f 10 01 } //3
		$a_01_1 = {69 64 65 6e 74 69 66 69 65 72 20 72 65 6d 6f 76 65 64 } //1 identifier removed
		$a_01_2 = {68 6f 73 74 20 75 6e 72 65 61 63 68 61 62 6c 65 } //1 host unreachable
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}
rule Trojan_Win32_Shelma_NS_MTB_2{
	meta:
		description = "Trojan:Win32/Shelma.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 45 78 65 63 } //1 WinExec
		$a_01_1 = {2f 00 63 00 76 00 2f 00 65 00 66 00 72 00 79 00 65 00 73 00 2e 00 65 00 78 00 65 00 } //1 /cv/efryes.exe
		$a_01_2 = {73 00 64 00 66 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 sdfer.exe
		$a_01_3 = {75 00 75 00 75 00 2e 00 72 00 75 00 6e 00 2e 00 70 00 6c 00 61 00 63 00 65 00 } //1 uuu.run.place
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}