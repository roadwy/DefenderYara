
rule Trojan_Win32_RedLineStealer_LSE_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.LSE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c8 81 e1 ?? ?? ?? ?? 79 ?? 49 81 c9 ?? ?? ?? ?? 41 8a 89 ?? ?? ?? ?? 88 4d fb 0f b6 45 fb 8b 0d ?? ?? ?? ?? 03 4d e0 0f be 11 33 d0 a1 ?? ?? ?? ?? 03 45 e0 88 10 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}