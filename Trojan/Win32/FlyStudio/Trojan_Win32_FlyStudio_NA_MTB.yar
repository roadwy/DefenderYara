
rule Trojan_Win32_FlyStudio_NA_MTB{
	meta:
		description = "Trojan:Win32/FlyStudio.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {74 06 81 cf ?? ?? ?? ?? 8b 4d dc 8b c1 c1 e0 ?? 8b 55 d8 03 c2 89 35 ?? ?? ?? ?? a3 04 f3 4f 00 89 0d ?? ?? ?? ?? 89 15 0c f3 4f 00 89 3d ?? ?? ?? ?? e8 f5 fe ff ff } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}