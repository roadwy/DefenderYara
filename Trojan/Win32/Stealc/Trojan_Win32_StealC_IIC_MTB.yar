
rule Trojan_Win32_StealC_IIC_MTB{
	meta:
		description = "Trojan:Win32/StealC.IIC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 70 8b 85 70 fe ff ff 01 45 70 8b 85 80 fe ff ff 8b f3 c1 e6 04 03 b5 6c fe ff ff 03 c3 33 f0 81 3d ?? ?? ?? ?? 03 0b 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}