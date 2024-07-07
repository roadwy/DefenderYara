
rule Trojan_Win32_RedlineStealer_XP_MTB{
	meta:
		description = "Trojan:Win32/RedlineStealer.XP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 55 f8 89 95 90 01 04 8b 85 90 01 04 33 85 90 01 04 b9 90 01 04 f7 e1 89 85 90 01 04 e9 90 01 04 ba 90 01 04 39 95 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}