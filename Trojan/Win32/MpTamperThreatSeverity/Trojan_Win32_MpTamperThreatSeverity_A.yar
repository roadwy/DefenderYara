
rule Trojan_Win32_MpTamperThreatSeverity_A{
	meta:
		description = "Trojan:Win32/MpTamperThreatSeverity.A,SIGNATURE_TYPE_CMDHSTR_EXT,16 00 01 00 05 00 00 "
		
	strings :
		$a_02_0 = {20 00 73 00 65 00 74 00 2d 00 6d 00 70 00 70 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 [0-10] 20 00 2d 00 75 00 6e 00 } //1
		$a_02_1 = {20 00 73 00 65 00 74 00 2d 00 6d 00 70 00 70 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 [0-10] 20 00 2d 00 6c 00 } //1
		$a_02_2 = {20 00 73 00 65 00 74 00 2d 00 6d 00 70 00 70 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 [0-10] 20 00 2d 00 6d 00 6f 00 } //1
		$a_02_3 = {20 00 73 00 65 00 74 00 2d 00 6d 00 70 00 70 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 [0-10] 20 00 2d 00 68 00 } //1
		$a_02_4 = {20 00 73 00 65 00 74 00 2d 00 6d 00 70 00 70 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 [0-10] 20 00 2d 00 73 00 65 00 76 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1) >=1
 
}