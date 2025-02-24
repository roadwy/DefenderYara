
rule Trojan_Win32_LummaStealerClick_Q_MTB{
	meta:
		description = "Trojan:Win32/LummaStealerClick.Q!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {68 00 74 00 74 00 70 00 } //1 http
		$a_00_2 = {2d 00 4a 00 6f 00 69 00 6e 00 } //1 -Join
		$a_00_3 = {49 00 60 00 45 00 60 00 58 00 } //1 I`E`X
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}