
rule Trojan_Win32_RedlineStealer_UG_MTB{
	meta:
		description = "Trojan:Win32/RedlineStealer.UG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 d0 0f b6 00 0f be d8 c7 44 24 90 01 05 c7 04 24 90 01 04 e8 90 01 04 0f af d8 89 d9 8b 55 90 01 01 8b 45 90 01 01 01 d0 0f b6 00 89 c2 89 c8 89 d1 31 c1 8b 55 90 01 01 8b 45 90 01 01 01 d0 89 ca 88 10 83 45 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}