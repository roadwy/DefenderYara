
rule Trojan_Win32_LummaStealerClick_Y_MTB{
	meta:
		description = "Trojan:Win32/LummaStealerClick.Y!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {6e 00 65 00 74 00 2e 00 77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 } //1 net.webclient
		$a_00_1 = {68 00 74 00 74 00 70 00 } //1 http
		$a_00_2 = {2e 00 6e 00 61 00 6d 00 65 00 } //1 .name
		$a_00_3 = {47 00 65 00 74 00 2d 00 4d 00 65 00 6d 00 62 00 65 00 72 00 } //1 Get-Member
		$a_00_4 = {76 00 61 00 6c 00 75 00 65 00 } //1 value
		$a_00_5 = {29 00 2e 00 49 00 6e 00 76 00 6f 00 6b 00 65 00 } //1 ).Invoke
		$a_00_6 = {57 00 68 00 65 00 72 00 65 00 7b 00 28 00 56 00 61 00 72 00 69 00 61 00 62 00 6c 00 65 00 } //1 Where{(Variable
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}