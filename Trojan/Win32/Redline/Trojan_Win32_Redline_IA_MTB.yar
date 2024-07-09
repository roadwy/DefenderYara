
rule Trojan_Win32_Redline_IA_MTB{
	meta:
		description = "Trojan:Win32/Redline.IA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 54 24 3c 01 54 24 14 c7 05 ?? ?? ?? ?? ee 3d ea f4 8b 44 24 2c 31 44 24 10 8b 44 24 10 31 44 24 14 83 3d } //10
		$a_03_1 = {56 69 72 74 c7 05 ?? ?? ?? ?? 75 61 6c 50 c7 05 ?? ?? ?? ?? 72 6f 74 65 c6 05 ?? ?? ?? ?? 63 ff 15 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}