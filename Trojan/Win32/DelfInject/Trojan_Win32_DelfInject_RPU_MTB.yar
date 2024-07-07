
rule Trojan_Win32_DelfInject_RPU_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.RPU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8b 40 fc 8b 40 04 83 e8 08 d1 e8 8b 55 08 89 42 f0 8b 45 08 8b 40 fc 83 c0 08 89 01 8b 45 08 8b 50 f0 4a 85 d2 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}