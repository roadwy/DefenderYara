
rule Trojan_Win32_Zenpak_ASAQ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ASAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 4d f6 0f b6 55 f7 31 d1 88 cb 88 5d f5 8b 0d ?? ?? ?? 10 81 e9 ?? ?? ?? 00 89 0d ?? ?? ?? 10 c7 05 [0-08] 0f b6 45 f5 83 c4 08 5e 5b 5d c3 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}