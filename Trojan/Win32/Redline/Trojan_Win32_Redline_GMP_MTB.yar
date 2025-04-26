
rule Trojan_Win32_Redline_GMP_MTB{
	meta:
		description = "Trojan:Win32/Redline.GMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {d1 e2 0b ca 88 4d ?? 0f b6 45 ?? 33 45 ?? 88 45 ?? 0f b6 4d ?? 81 c1 ?? ?? ?? ?? 88 4d ?? 0f b6 55 ?? 83 f2 ?? 88 55 ?? 0f b6 45 ?? 03 45 ?? 88 45 ?? 0f b6 4d ?? f7 d1 88 4d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}