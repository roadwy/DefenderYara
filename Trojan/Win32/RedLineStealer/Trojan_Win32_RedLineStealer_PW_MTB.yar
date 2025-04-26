
rule Trojan_Win32_RedLineStealer_PW_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.PW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 ca 89 4c 24 ?? 89 5c 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 54 24 ?? 89 54 24 ?? 89 1d ?? ?? ?? ?? 8b 44 24 ?? 29 44 24 ?? 8b 44 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}