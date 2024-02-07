
rule Trojan_Win32_CryptInject_B_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {eb 00 31 0d 90 01 04 c7 05 90 01 04 00 00 00 00 a1 90 01 04 01 05 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 90 00 } //01 00 
		$a_03_1 = {8b 4d fc 03 0d 90 01 04 8b 55 f4 03 15 90 01 04 8a 02 88 01 33 c9 0f 90 00 } //00 00 
		$a_00_2 = {7e } //15 00  ~
	condition:
		any of ($a_*)
 
}