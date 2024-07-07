
rule Trojan_Win32_Amadey_PAC_MTB{
	meta:
		description = "Trojan:Win32/Amadey.PAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 05 03 45 e4 c7 05 90 01 08 89 45 0c 33 c3 31 45 08 8b 45 08 29 45 f8 8b 45 e0 29 45 fc ff 4d f4 8b 45 f8 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}