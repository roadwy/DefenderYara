
rule Trojan_Win32_Qakbot_DC{
	meta:
		description = "Trojan:Win32/Qakbot.DC,SIGNATURE_TYPE_CMDHSTR_EXT,28 00 28 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {72 00 6d 00 64 00 69 00 72 00 } //0a 00  rmdir
		$a_00_1 = {45 00 6d 00 61 00 69 00 6c 00 53 00 74 00 6f 00 72 00 61 00 67 00 65 00 } //0a 00  EmailStorage
		$a_00_2 = {20 00 2f 00 51 00 20 00 } //0a 00   /Q 
		$a_00_3 = {20 00 2f 00 53 00 20 00 } //00 00   /S 
	condition:
		any of ($a_*)
 
}