
rule Trojan_Win32_SmokeLoader_EAC_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.EAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 55 ec 8d 04 1f 33 d0 33 55 fc 89 55 dc 8b 45 dc 29 45 f8 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}