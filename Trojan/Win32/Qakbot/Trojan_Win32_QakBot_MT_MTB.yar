
rule Trojan_Win32_QakBot_MT_MTB{
	meta:
		description = "Trojan:Win32/QakBot.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {89 08 5d c3 90 0a 30 00 31 0d 90 01 04 eb 00 c7 05 90 02 08 a1 90 01 04 01 05 90 01 04 a1 90 01 04 8b 0d 90 00 } //01 00 
		$a_01_1 = {63 00 3a 00 5c 00 6d 00 69 00 72 00 63 00 5c 00 6d 00 69 00 72 00 63 00 2e 00 69 00 6e 00 69 00 } //00 00 
	condition:
		any of ($a_*)
 
}