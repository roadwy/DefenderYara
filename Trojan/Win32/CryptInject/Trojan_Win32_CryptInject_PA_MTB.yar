
rule Trojan_Win32_CryptInject_PA_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b cf c1 f9 1f 8b d1 33 c8 33 d6 3b ca 7f 22 8b 4d 0c 8b 09 8b 51 0c 8b 71 14 2b d6 8a 0c 02 8d 34 02 8b d0 33 cb 83 e2 20 33 ca 03 c7 88 0e eb cc 90 09 03 00 8b 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}