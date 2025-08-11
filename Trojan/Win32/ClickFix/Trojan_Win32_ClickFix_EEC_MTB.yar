
rule Trojan_Win32_ClickFix_EEC_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.EEC!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 74 00 6e 00 } //1 schtasks /create /tn
		$a_00_1 = {24 00 65 00 6e 00 76 00 3a 00 } //1 $env:
		$a_00_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_3 = {68 00 69 00 64 00 64 00 65 00 6e 00 } //1 hidden
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule Trojan_Win32_ClickFix_EEC_MTB_2{
	meta:
		description = "Trojan:Win32/ClickFix.EEC!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 00 75 00 72 00 6c 00 20 00 2d 00 6f 00 } //1 curl -o
		$a_00_1 = {2e 00 7a 00 69 00 70 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 90 00 02 00 06 00 2e 00 90 00 02 00 06 00 2e 00 90 00 02 00 06 00 2e 00 90 00 02 00 3c 00 2e 00 74 00 78 00 74 00 } //1
		$a_00_2 = {63 00 6d 00 64 00 20 00 2f 00 63 00 } //1 cmd /c
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}