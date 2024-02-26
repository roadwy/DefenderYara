
rule Trojan_Win32_CryptInject_LA_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.LA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 48 4a 64 76 67 68 63 67 79 68 75 73 68 67 6a 64 73 68 67 6a } //01 00  dHJdvghcgyhushgjdshgj
		$a_01_1 = {64 8b 3d 30 00 00 00 8b 7f 0c 8b 77 0c 8b 06 8b 00 8b 40 18 } //00 00 
	condition:
		any of ($a_*)
 
}