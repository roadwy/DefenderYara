
rule Trojan_Win32_CryptInject_DR_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.DR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {01 44 24 0c 8b 54 24 0c 8a 04 32 8b 0d 90 02 04 88 04 0e 83 3d 90 02 04 44 75 12 90 00 } //02 00 
		$a_03_1 = {8d 04 3b 33 44 24 10 33 c1 81 3d 90 02 04 a3 01 00 00 89 44 24 10 75 22 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}