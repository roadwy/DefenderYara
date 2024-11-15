
rule Trojan_Win32_LummaStealer_YAD_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.YAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 14 2d ?? ?? ?? ?? 89 44 24 04 8b 44 24 08 33 44 24 04 89 04 24 8b 04 24 05 ?? ?? ?? ?? 05 ?? ?? ?? ?? 2d ?? ?? ?? ?? 83 c0 01 0f b6 c0 } //11
	condition:
		((#a_03_0  & 1)*11) >=11
 
}