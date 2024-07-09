
rule Trojan_Win32_StealC_ANG_MTB{
	meta:
		description = "Trojan:Win32/StealC.ANG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 04 13 d3 ea 89 45 ec c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 d4 8b 45 ec 31 45 fc 33 55 fc 81 3d ?? ?? ?? ?? 13 02 00 00 89 55 ec 75 } //1
		$a_01_1 = {56 56 ff 15 9c 10 40 00 31 7d fc 8b 45 fc 29 45 f0 81 c3 47 86 c8 61 ff 4d e8 0f 85 ad fe ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}