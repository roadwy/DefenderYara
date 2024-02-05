
rule Trojan_Win32_QakbotOnephish_A{
	meta:
		description = "Trojan:Win32/QakbotOnephish.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 90 02 f0 5c 00 74 00 65 00 6d 00 70 00 5c 00 6f 00 6e 00 65 00 6e 00 6f 00 74 00 65 00 5c 00 90 02 f0 2e 00 68 00 74 00 61 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}