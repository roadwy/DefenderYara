
rule Trojan_Win32_Redline_IMF_MTB{
	meta:
		description = "Trojan:Win32/Redline.IMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e2 06 0b ca 88 4d ?? 0f b6 45 ?? 83 c0 48 88 45 ?? 0f b6 4d ?? c1 f9 02 0f b6 55 ?? c1 e2 06 0b ca 88 4d ?? 0f b6 45 ?? 2d ?? 00 00 00 88 45 ?? 0f b6 4d ?? f7 d9 88 4d ?? 8b 55 e0 8a 45 ?? 88 44 15 e4 e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}