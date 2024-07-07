
rule Trojan_Win32_RedlineStealer_UF_MTB{
	meta:
		description = "Trojan:Win32/RedlineStealer.UF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 f7 e6 89 c8 c1 ea 90 01 01 6b d2 90 01 01 29 d0 0f be 80 90 01 04 69 c0 90 01 04 30 81 90 01 04 83 c1 90 01 01 81 f9 90 01 04 75 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}