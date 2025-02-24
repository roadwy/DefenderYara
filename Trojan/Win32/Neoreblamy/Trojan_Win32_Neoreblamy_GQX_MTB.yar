
rule Trojan_Win32_Neoreblamy_GQX_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.GQX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {eb 0d 0f b6 45 ?? 0f b6 4d ?? 0b c1 89 45 ?? 8a 45 ?? 88 45 ?? 8b 45 ?? d1 e0 89 45 ?? 0f b6 45 ?? 0b 45 ?? 89 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}