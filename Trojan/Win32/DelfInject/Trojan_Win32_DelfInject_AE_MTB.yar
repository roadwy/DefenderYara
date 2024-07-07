
rule Trojan_Win32_DelfInject_AE_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e0 8b 00 89 45 d4 8b 45 e0 83 c0 04 89 45 e0 8b 45 d8 89 45 dc 8b 45 dc 83 e8 04 89 45 dc 33 c0 89 45 bc 33 c0 89 45 b8 c7 45 cc 6e c3 01 00 33 c0 89 45 c4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}