
rule Trojan_Win32_Shelma_NS_MTB{
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