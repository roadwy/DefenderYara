
rule Trojan_Win32_LummaStealer_DV_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.DV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 b4 3c ?? ?? ?? ?? 89 fd 09 f5 21 fe 89 f0 83 e0 38 35 ?? ?? ?? ?? 89 f2 81 f2 ?? ?? ?? ?? 81 ce ?? ?? ?? ?? 21 d6 09 c6 81 f6 ?? ?? ?? ?? 21 ee 89 74 24 28 8b 44 24 28 04 88 88 84 3c } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}