
rule Trojan_Win32_SusNodeExec_ABB_MTB{
	meta:
		description = "Trojan:Win32/SusNodeExec.ABB!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 } //1 cmd.exe
		$a_00_1 = {2f 00 43 00 20 00 73 00 74 00 61 00 72 00 74 00 } //1 /C start
		$a_00_2 = {2f 00 6d 00 69 00 6e 00 } //1 /min
		$a_00_3 = {5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 73 00 5c 00 4d 00 61 00 6e 00 75 00 61 00 6c 00 52 00 65 00 61 00 64 00 65 00 72 00 50 00 72 00 6f 00 5c 00 6e 00 6f 00 64 00 65 00 5c 00 6e 00 6f 00 64 00 65 00 2e 00 65 00 78 00 65 00 } //1 \AppData\Local\Programs\ManualReaderPro\node\node.exe
		$a_00_4 = {2e 00 6a 00 73 00 } //1 .js
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}