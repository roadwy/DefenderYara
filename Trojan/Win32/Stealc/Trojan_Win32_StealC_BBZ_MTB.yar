
rule Trojan_Win32_StealC_BBZ_MTB{
	meta:
		description = "Trojan:Win32/StealC.BBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 05 89 45 74 8b 85 10 ff ff ff 01 45 74 8b 8d 3c ff ff ff 8b c7 c1 e0 04 03 85 ?? ?? ?? ?? 03 cf 33 c1 81 3d ?? ?? ?? ?? 03 0b 00 00 89 85 1c ff ff ff 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}