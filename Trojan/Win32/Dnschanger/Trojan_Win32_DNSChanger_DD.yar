
rule Trojan_Win32_DNSChanger_DD{
	meta:
		description = "Trojan:Win32/DNSChanger.DD,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 73 00 61 00 6c 00 74 00 6c 00 6f 00 67 00 90 02 15 2e 00 72 00 75 00 2f 00 6c 00 6f 00 67 00 90 00 } //01 00 
		$a_02_1 = {68 74 74 70 73 3a 2f 2f 73 61 6c 74 6c 6f 67 90 02 15 2e 72 75 2f 6c 6f 67 90 00 } //01 00 
		$a_00_2 = {43 62 79 50 49 4e 62 4d 52 42 6c 57 79 6d 72 32 } //00 00 
	condition:
		any of ($a_*)
 
}