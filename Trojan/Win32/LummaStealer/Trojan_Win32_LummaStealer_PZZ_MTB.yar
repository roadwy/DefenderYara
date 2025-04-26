
rule Trojan_Win32_LummaStealer_PZZ_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.PZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 ec c1 e8 05 89 45 f8 8b 45 dc 01 45 f8 8d 0c 3b 33 f1 81 3d ?? ?? ?? ?? e6 09 00 00 c7 05 ?? ?? ?? ?? ee 3d ea f4 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}