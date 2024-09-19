
rule Trojan_Win32_Socgolsh_SG{
	meta:
		description = "Trojan:Win32/Socgolsh.SG,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 66 00 20 00 2f 00 74 00 6e 00 } //1 schtasks /create /f /tn
		$a_02_1 = {5c 00 70 00 79 00 74 00 68 00 6f 00 6e 00 77 00 2e 00 65 00 78 00 65 00 [0-ff] 2e 00 70 00 79 00 20 00 2d 00 69 00 70 00 [0-ff] 2d 00 70 00 6f 00 72 00 74 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}