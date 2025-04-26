
rule Trojan_Win32_LummaStealer_CCGW_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CCGW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 d1 41 ff e1 31 c9 3d ?? ?? ?? ?? 0f 9c c1 8b 0c 8d ?? ?? ?? ?? ba ?? ?? ?? ?? 33 15 ?? ?? ?? ?? 01 d1 41 ff e1 31 c9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}