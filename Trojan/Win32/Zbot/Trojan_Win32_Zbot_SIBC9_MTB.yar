
rule Trojan_Win32_Zbot_SIBC9_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SIBC9!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {53 85 c0 75 ?? 90 90 58 2b f0 8b d8 50 51 8b c7 90 13 57 8b 08 5f e8 ?? ?? ?? ?? 90 13 33 c1 8b 06 fe cd 33 c1 90 13 8b c8 46 88 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}