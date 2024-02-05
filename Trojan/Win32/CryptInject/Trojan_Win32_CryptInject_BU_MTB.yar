
rule Trojan_Win32_CryptInject_BU_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {ac 32 02 aa 42 49 83 ec 04 c7 04 24 93 dc 00 05 83 c4 04 85 c9 75 } //05 00 
		$a_01_1 = {ac 83 ec 04 c7 04 24 5e d0 7d db 83 c4 04 32 02 aa 42 49 85 c9 75 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CryptInject_BU_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.BU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 5d f8 03 de 8a 01 88 45 f5 8b c6 51 b9 03 00 00 00 33 d2 f7 f1 59 85 d2 75 11 8a 45 f5 32 45 f6 88 03 8a 03 32 45 f7 88 03 eb 05 8a 45 f5 88 03 46 41 4f 75 ca } //00 00 
	condition:
		any of ($a_*)
 
}