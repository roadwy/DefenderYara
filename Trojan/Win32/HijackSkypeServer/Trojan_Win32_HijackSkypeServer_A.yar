
rule Trojan_Win32_HijackSkypeServer_A{
	meta:
		description = "Trojan:Win32/HijackSkypeServer.A,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 02 00 00 0a 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 } //0a 00 
		$a_00_1 = {63 00 6d 00 64 00 20 00 2f 00 63 00 } //00 00 
	condition:
		any of ($a_*)
 
}