
rule Trojan_Win32_ClickFix_DCI_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DCI!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,6f 00 6f 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 00 5e 00 75 00 72 00 5e 00 6c 00 2e 00 65 00 78 00 5e 00 65 00 } //100 c^ur^l.ex^e
		$a_00_1 = {2d 00 6b 00 20 00 2d 00 53 00 73 00 20 00 2d 00 58 00 } //10 -k -Ss -X
		$a_00_2 = {26 00 26 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 2f 00 6d 00 69 00 6e 00 } //1 && start /min
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1) >=111
 
}