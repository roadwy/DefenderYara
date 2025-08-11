
rule Trojan_Win32_ClickFix_EEP_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.EEP!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {67 00 77 00 6d 00 69 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 53 00 79 00 73 00 74 00 65 00 6d 00 } //1 gwmi Win32_ComputerSystem
		$a_00_1 = {23 00 56 00 65 00 72 00 69 00 66 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 43 00 6f 00 64 00 65 00 } //1 #Verification Code
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}