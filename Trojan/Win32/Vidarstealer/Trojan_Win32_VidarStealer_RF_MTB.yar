
rule Trojan_Win32_VidarStealer_RF_MTB{
	meta:
		description = "Trojan:Win32/VidarStealer.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 f6 8b e9 85 ff 0f 8e ?? ?? ?? ?? 53 e8 ?? ?? ?? ?? 30 04 2e 81 ff 49 06 00 00 0f 85 ?? ?? ?? ?? 83 64 24 ?? 00 81 6c 24 ?? f4 ca bb 26 c1 e0 17 81 44 24 ?? 7e 2b 83 22 81 f3 da 61 0c 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}