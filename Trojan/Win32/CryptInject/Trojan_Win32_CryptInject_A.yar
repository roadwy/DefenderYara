
rule Trojan_Win32_CryptInject_A{
	meta:
		description = "Trojan:Win32/CryptInject.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c0 55 8b ec 8b 45 90 01 01 90 90 90 90 8a 10 80 f2 90 01 01 88 10 90 90 90 90 5d 90 00 } //01 00 
		$a_03_1 = {33 c0 89 06 8b 06 03 c3 73 90 01 01 e8 90 01 04 50 ff 15 60 6e 46 00 90 90 90 90 ff 06 81 3e c5 5a 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}