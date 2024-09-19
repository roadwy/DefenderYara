
rule Trojan_Win32_SmokeLoader_AXA_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.AXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c1 8b 4d 70 33 c7 2b f0 8b c6 c1 e8 05 89 b5 ?? ?? ?? ?? 03 ce 89 45 6c 8b 85 ?? ?? ?? ?? 01 45 6c c1 e6 04 03 b5 68 fe ff ff 33 f1 81 3d ?? ?? ?? ?? 03 0b 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}