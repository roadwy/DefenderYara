
rule Trojan_Win32_VidarStealer_RF_MTB{
	meta:
		description = "Trojan:Win32/VidarStealer.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 f6 8b e9 85 ff 0f 8e 90 01 04 53 e8 90 01 04 30 04 2e 81 ff 49 06 00 00 0f 85 90 01 04 83 64 24 90 01 01 00 81 6c 24 90 01 01 f4 ca bb 26 c1 e0 17 81 44 24 90 01 01 7e 2b 83 22 81 f3 da 61 0c 08 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}