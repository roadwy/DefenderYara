
rule Trojan_Win32_Zusy_BAC_MTB{
	meta:
		description = "Trojan:Win32/Zusy.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 14 10 33 ca 8b 45 08 03 45 98 0f b6 30 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Zusy_BAC_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {b9 62 00 00 00 f3 a4 8d 85 62 ff ff ff 89 04 24 e8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}