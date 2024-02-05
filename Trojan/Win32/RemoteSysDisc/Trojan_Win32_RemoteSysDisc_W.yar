
rule Trojan_Win32_RemoteSysDisc_W{
	meta:
		description = "Trojan:Win32/RemoteSysDisc.W,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {6e 00 6c 00 74 00 65 00 73 00 74 00 90 02 10 2f 00 64 00 73 00 67 00 65 00 74 00 64 00 63 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}