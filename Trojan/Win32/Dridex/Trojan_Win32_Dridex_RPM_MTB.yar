
rule Trojan_Win32_Dridex_RPM_MTB{
	meta:
		description = "Trojan:Win32/Dridex.RPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 cf 4a 89 4c 24 34 89 54 24 2c 8a 00 88 85 ?? ?? ?? ?? 45 8b 44 24 24 8b 3d ?? ?? ?? ?? 03 c0 89 6c 24 28 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}