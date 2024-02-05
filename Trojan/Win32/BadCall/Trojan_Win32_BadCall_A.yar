
rule Trojan_Win32_BadCall_A{
	meta:
		description = "Trojan:Win32/BadCall.A,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 } //05 00 
		$a_02_1 = {2f 00 73 00 20 00 2f 00 64 00 20 00 2f 00 63 00 90 02 08 63 00 61 00 6c 00 6c 00 20 00 25 00 90 02 08 3a 00 90 02 10 3d 00 25 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}