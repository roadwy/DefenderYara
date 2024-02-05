
rule Trojan_Win32_CryptInject_SD_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 8b ec a1 90 01 04 a3 90 01 04 8b 0d 90 01 04 8b 11 89 15 90 01 04 a1 90 01 04 83 e8 01 a3 90 02 08 8b 15 90 01 04 8b c0 83 c2 01 90 01 02 a1 90 01 04 8b c0 8b ca 8b c0 a3 90 01 04 8b c0 31 0d 90 01 04 8b c0 a1 90 01 04 c7 05 90 01 04 00 00 00 00 01 05 90 01 04 8b 0d 90 01 04 8b 15 90 01 04 89 11 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CryptInject_SD_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.SD!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 50 72 6f 67 72 61 6d 6d 65 5c 41 75 74 6f 73 74 61 72 74 5c } //01 00 
		$a_01_1 = {5c 65 78 63 2e 65 78 65 } //01 00 
		$a_01_2 = {57 69 6e 33 32 2e 63 72 41 63 6b 65 72 2e 41 } //01 00 
		$a_01_3 = {79 6f 75 70 6f 72 6e 2e 63 6f 6d } //01 00 
		$a_01_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //00 00 
	condition:
		any of ($a_*)
 
}