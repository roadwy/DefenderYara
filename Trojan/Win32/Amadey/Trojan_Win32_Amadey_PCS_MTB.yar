
rule Trojan_Win32_Amadey_PCS_MTB{
	meta:
		description = "Trojan:Win32/Amadey.PCS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 51 89 4c 24 90 01 01 ff 15 90 01 04 6a 90 01 01 6a 90 01 01 6a 90 01 01 ff 15 90 01 04 6a 90 01 01 8d 4c 24 90 01 01 51 6a 90 01 01 68 90 01 04 6a 90 01 01 6a 90 01 01 ff 15 90 01 04 31 7c 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 8b 0d 90 01 04 81 f9 90 01 04 74 90 01 01 81 c3 90 01 04 ff 4c 24 90 01 01 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}