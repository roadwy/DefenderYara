
rule Trojan_Win32_ClickFix_DEY_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DEY!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,79 00 79 00 06 00 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 } //100 msiexec
		$a_00_1 = {2f 00 6e 00 6f 00 72 00 65 00 73 00 74 00 61 00 72 00 74 00 } //10 /norestart
		$a_00_2 = {2f 00 70 00 61 00 63 00 6b 00 61 00 67 00 65 00 } //10 /package
		$a_00_3 = {2f 00 70 00 61 00 73 00 73 00 69 00 76 00 65 00 } //10 /passive
		$a_00_4 = {2e 00 6d 00 73 00 69 00 } //1 .msi
		$a_00_5 = {2e 00 74 00 78 00 74 00 } //1 .txt
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=121
 
}