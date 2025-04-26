
rule Trojan_Win32_Zenpak_GPPB_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GPPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 8a 45 ?? 8a 4d ?? 31 d2 88 d4 88 c5 02 2d ?? ?? ?? ?? 88 2d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? 8b 15 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}