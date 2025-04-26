
rule Trojan_Win32_Gozi_MX_MTB{
	meta:
		description = "Trojan:Win32/Gozi.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e9 05 03 4d ?? 03 45 ?? 33 c1 8b 4d ?? 03 cf 33 c1 29 45 ?? 81 3d ?? ?? ?? ?? d5 01 00 00 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}