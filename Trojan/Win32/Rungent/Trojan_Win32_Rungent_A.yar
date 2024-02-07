
rule Trojan_Win32_Rungent_A{
	meta:
		description = "Trojan:Win32/Rungent.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 31 36 30 2e 32 30 32 2e 31 36 32 2e 31 34 37 2f 31 2e 74 6d 70 } //01 00  http://160.202.162.147/1.tmp
		$a_01_1 = {68 74 74 70 3a 2f 2f 35 2e 31 34 39 2e 32 35 34 2e 32 35 2f 31 2e 74 6d 70 } //01 00  http://5.149.254.25/1.tmp
		$a_01_2 = {25 73 5c 4d 69 63 72 6f 73 6f 66 74 73 20 48 65 49 70 5c 74 65 6d 70 6c 61 74 65 5f 25 78 2e 44 41 54 41 48 41 53 48 } //00 00  %s\Microsofts HeIp\template_%x.DATAHASH
	condition:
		any of ($a_*)
 
}