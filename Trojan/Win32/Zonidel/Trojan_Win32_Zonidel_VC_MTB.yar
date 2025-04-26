
rule Trojan_Win32_Zonidel_VC_MTB{
	meta:
		description = "Trojan:Win32/Zonidel.VC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cf 8b c7 c1 e9 ?? 03 4c 24 ?? c1 e0 ?? 03 44 24 ?? 33 c8 8d 04 3b 33 c8 8b 44 24 ?? 2b f1 b9 ?? ?? ?? ?? 2b c8 03 d9 4d 75 ?? 8b 6c 24 ?? 89 7d ?? 5f 89 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}