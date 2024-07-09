
rule Trojan_Win32_Zbot_SIBC5_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SIBC5!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 e8 01 f8 89 c5 8a 26 8a 3f 88 e0 88 fb 88 c4 88 df 30 fc 88 27 41 47 46 39 ef 7d ?? 39 d1 7d ?? eb ?? 31 c9 29 d6 eb } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}