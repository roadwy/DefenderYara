
rule Trojan_Win32_LummaStealer_MF_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 40 04 2d ?? ?? ?? ?? 01 47 68 a1 ?? ?? ?? ?? 8b 48 3c 8b 47 54 83 c1 ?? 03 c1 8b 8f a4 00 00 00 0f af 87 a0 00 00 00 89 87 a0 00 00 00 a1 ?? ?? ?? ?? 88 1c 08 ff 05 ?? ?? ?? ?? 81 fd ?? ?? ?? ?? 0f 8c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}