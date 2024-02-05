
rule Trojan_Win32_CryptInject_CW_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.CW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {01 45 e8 8b 45 e8 8a 04 30 8b 0d 90 02 04 88 04 31 83 3d 90 02 04 44 75 24 90 00 } //02 00 
		$a_01_1 = {3d 4b 79 02 0f 7f 08 40 3d b2 59 62 73 7c f1 } //00 00 
	condition:
		any of ($a_*)
 
}