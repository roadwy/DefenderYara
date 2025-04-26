
rule Trojan_Win32_Hancitor_GPU_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.GPU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 3b 2b f1 83 ee 4a 81 3d ?? ?? ?? ?? f6 1a 00 00 8b ce 75 ?? 2b 2d ?? ?? ?? ?? 8d 51 ?? 0f af ea 8d 54 01 ?? 0f b7 f2 0f b7 f6 81 c7 dc af 0d 01 8b d6 2b 15 ?? ?? ?? ?? 89 3b 83 c3 04 83 6c 24 10 01 89 3d ?? ?? ?? ?? 8d 4c 11 50 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}