
rule Trojan_Win32_Raccoon_CG_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_03_0 = {59 50 56 ff d3 6a 90 01 01 ba 90 01 04 a3 90 01 04 b9 90 01 04 e8 90 01 04 59 90 00 } //6
		$a_81_1 = {47 65 74 4f 62 6a 65 63 74 57 } //1 GetObjectW
		$a_81_2 = {43 6f 44 65 63 6f 64 65 50 72 6f 78 79 } //1 CoDecodeProxy
		$a_81_3 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 CheckRemoteDebuggerPresent
		$a_81_4 = {2a 2e 6c 6e 6b } //1 *.lnk
	condition:
		((#a_03_0  & 1)*6+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=10
 
}