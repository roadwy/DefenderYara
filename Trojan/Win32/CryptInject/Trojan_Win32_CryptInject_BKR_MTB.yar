
rule Trojan_Win32_CryptInject_BKR_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BKR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 a1 30 00 00 00 8b 50 0c 8b 42 14 83 c2 14 3b c2 74 11 } //00 00 
	condition:
		any of ($a_*)
 
}