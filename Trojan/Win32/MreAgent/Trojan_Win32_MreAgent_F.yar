
rule Trojan_Win32_MreAgent_F{
	meta:
		description = "Trojan:Win32/MreAgent.F,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {5c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 5c 00 72 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 5c 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 6d 00 73 00 78 00 73 00 6c 00 2e 00 65 00 78 00 65 00 [0-ff] 2e 00 74 00 78 00 74 00 20 00 [0-ff] 2e 00 74 00 78 00 74 00 } //1
		$a_00_1 = {20 00 2d 00 6f 00 20 00 } //-100  -o 
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*-100) >=1
 
}