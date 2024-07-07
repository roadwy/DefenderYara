
rule Trojan_Win32_Amadey_KL_MTB{
	meta:
		description = "Trojan:Win32/Amadey.KL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 dc 31 45 e4 8b 45 f8 33 45 e4 2b f8 89 45 f8 8b c7 c1 e0 04 89 7d dc 89 45 fc 8b 45 c8 01 45 fc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}