
rule Trojan_Win32_CryptInject_SC_MSR{
	meta:
		description = "Trojan:Win32/CryptInject.SC!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 65 74 6e 61 6d 65 69 6e 66 6f } //01 00  getnameinfo
		$a_01_1 = {7a 69 70 63 72 79 70 74 } //01 00  zipcrypt
		$a_01_2 = {66 61 6b 65 63 72 63 33 32 } //01 00  fakecrc32
		$a_01_3 = {65 00 6e 00 61 00 62 00 6c 00 65 00 73 00 20 00 44 00 61 00 74 00 61 00 20 00 63 00 6f 00 6c 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 } //00 00  enables Data collection
	condition:
		any of ($a_*)
 
}