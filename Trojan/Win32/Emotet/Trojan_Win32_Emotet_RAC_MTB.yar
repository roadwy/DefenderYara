
rule Trojan_Win32_Emotet_RAC_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {b9 53 1b 00 00 f7 f9 45 0f b6 94 14 90 01 04 30 55 90 01 01 8b 84 24 90 01 04 83 c0 90 01 01 c7 84 24 90 01 04 01 00 00 00 8d 48 90 01 01 83 ca ff 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}