
rule Trojan_Win32_SuspPing_A{
	meta:
		description = "Trojan:Win32/SuspPing.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 00 69 00 6e 00 67 00 20 00 2d 00 74 00 20 00 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 } //00 00  ping -t 127.0.0.1
	condition:
		any of ($a_*)
 
}