
rule Trojan_Win32_RedlineStealer_AK1_MTB{
	meta:
		description = "Trojan:Win32/RedlineStealer.AK1!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 83 c0 01 89 45 fc 81 7d fc b2 f2 f5 05 7d 0b 8b 4d f8 83 c1 01 89 4d f8 eb e3 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}