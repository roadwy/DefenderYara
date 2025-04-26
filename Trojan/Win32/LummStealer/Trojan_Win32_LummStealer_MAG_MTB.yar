
rule Trojan_Win32_LummStealer_MAG_MTB{
	meta:
		description = "Trojan:Win32/LummStealer.MAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e0 04 89 45 fc 8b 45 e0 01 45 fc 8b 4d ?? 8b c6 8b 55 fc d3 e8 03 45 ?? 89 45 ec 89 45 f0 8d 04 33 33 d0 81 3d ?? ?? ?? ?? 03 0b 00 00 89 55 fc 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}