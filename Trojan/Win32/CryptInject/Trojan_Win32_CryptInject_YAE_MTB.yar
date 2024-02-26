
rule Trojan_Win32_CryptInject_YAE_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.YAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 ec 04 c7 04 24 90 01 04 5b 21 c1 e8 90 01 04 b9 3c 29 e5 1c 31 1f 81 c0 0b 6f f6 5a 81 c7 02 00 00 00 29 c0 b9 27 53 e5 1d 39 d7 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}