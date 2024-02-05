
rule Trojan_Win32_CryptInject_AL_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {38 43 77 6d 62 33 49 30 2b 33 73 61 63 76 54 76 68 } //01 00 
		$a_01_1 = {80 3a 00 74 f8 90 ac 32 02 aa 42 e2 f3 } //01 00 
		$a_01_2 = {59 74 79 76 75 62 49 62 68 67 } //01 00 
		$a_01_3 = {55 6a 6b 6e 62 68 6a 53 74 63 76 67 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CryptInject_AL_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b d3 8b c7 e8 90 01 02 ff ff 43 81 fb 90 01 02 00 00 75 ee 90 00 } //01 00 
		$a_02_1 = {8b c8 03 ca 90 05 10 01 90 b0 90 01 01 90 05 10 01 90 32 82 90 01 03 00 90 05 10 01 90 88 01 90 05 10 01 90 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}