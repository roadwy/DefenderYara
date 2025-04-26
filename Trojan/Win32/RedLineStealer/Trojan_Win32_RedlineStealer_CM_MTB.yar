
rule Trojan_Win32_RedlineStealer_CM_MTB{
	meta:
		description = "Trojan:Win32/RedlineStealer.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 31 c9 89 e5 53 8b 5d ?? 3b 4d ?? ?? ?? 89 c8 31 d2 f7 75 ?? 8b 45 ?? 0f be 04 10 69 c0 ?? ?? ?? ?? 30 04 0b 41 ?? ?? 5b 5d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}