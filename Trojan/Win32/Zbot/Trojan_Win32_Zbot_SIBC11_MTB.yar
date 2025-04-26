
rule Trojan_Win32_Zbot_SIBC11_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SIBC11!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 f0 58 53 57 8b d8 53 85 c0 75 ?? 90 90 58 2b f0 8b d8 50 51 8b c7 90 18 57 8b 08 5f e8 ?? ?? ?? ?? 90 18 41 33 c0 8b 06 49 33 c1 90 18 8b c8 46 88 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}