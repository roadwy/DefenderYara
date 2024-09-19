
rule Trojan_Win32_SmokeLoader_WRD_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.WRD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c7 2b f0 8b c6 c1 e8 05 03 ce 89 45 ?? 8b 85 ?? fd ff ff 01 45 ?? 8b c6 c1 e0 04 03 85 ?? fd ff ff 33 45 ?? 33 c1 2b d8 89 9d ?? fd ff ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}