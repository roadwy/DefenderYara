
rule Trojan_Win32_Qakbot_SA{
	meta:
		description = "Trojan:Win32/Qakbot.SA,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 90 02 05 2d 00 73 00 69 00 6c 00 65 00 6e 00 74 00 90 02 05 2e 00 2e 00 5c 00 78 00 65 00 72 00 74 00 69 00 73 00 90 02 01 2e 00 64 00 6c 00 6c 00 90 00 } //0a 00 
		$a_02_1 = {72 65 67 73 76 72 33 32 90 02 05 2d 73 69 6c 65 6e 74 90 02 05 2e 2e 5c 78 65 72 74 69 73 90 02 01 2e 64 6c 6c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}