
rule Trojan_Win32_Babar_AMP_MTB{
	meta:
		description = "Trojan:Win32/Babar.AMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 d1 8b 0d ?? ?? ?? ?? 03 f8 88 15 [0-1e] 81 e3 ff 00 00 00 83 e7 04 03 d2 03 cf 8b 3d ?? ?? ?? ?? 83 e7 0c 33 c0 0f af fb 0b d1 [0-1e] 33 df 3b d1 89 44 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}