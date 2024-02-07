
rule Trojan_Win32_NetWire_RA_{
	meta:
		description = "Trojan:Win32/NetWire.RA!!NetWire.A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4c 6f 67 73 5c } //01 00  AppData\Roaming\Logs\
		$a_81_1 = {48 6f 73 74 49 64 } //01 00  HostId
		$a_81_2 = {53 4f 46 54 57 41 52 45 5c 4e 65 74 57 69 72 65 } //01 00  SOFTWARE\NetWire
		$a_81_3 = {49 6e 73 74 61 6c 6c 20 44 61 74 65 } //00 00  Install Date
	condition:
		any of ($a_*)
 
}