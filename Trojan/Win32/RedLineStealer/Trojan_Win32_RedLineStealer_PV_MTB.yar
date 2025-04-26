
rule Trojan_Win32_RedLineStealer_PV_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.PV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 81 c9 00 ff ff ff 41 8a 89 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 8d c4 fc ff ff 0f be 11 33 d0 a1 ?? ?? ?? ?? 03 85 c4 fc ff ff 88 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}