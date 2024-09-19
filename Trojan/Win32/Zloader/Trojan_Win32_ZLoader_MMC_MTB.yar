
rule Trojan_Win32_ZLoader_MMC_MTB{
	meta:
		description = "Trojan:Win32/ZLoader.MMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b f3 c1 ee 05 03 75 e4 03 fa 03 c3 33 f8 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75 } //5
		$a_03_1 = {c1 e9 05 03 4d e8 c7 05 ?? ?? ?? ?? 84 10 d6 cb 33 cf 33 ce c7 05 ?? ?? ?? ?? ff ff ff ff 2b d9 8b 45 ec 29 45 f8 83 6d f4 01 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}