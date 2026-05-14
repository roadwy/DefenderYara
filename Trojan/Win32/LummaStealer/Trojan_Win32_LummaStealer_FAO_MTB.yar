
rule Trojan_Win32_LummaStealer_FAO_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.FAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 c1 89 c8 35 00 01 00 00 21 c8 8a 84 04 ?? ?? ?? ?? 8b 4c ?? 3c 8a 54 0d 00 88 d4 f6 d4 20 c4 f6 d0 20 d0 08 e0 88 44 0d 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_LummaStealer_FAO_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.FAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {c0 e0 05 32 d0 8b 44 24 24 32 d1 8b cf 32 d3 8b 5c 24 18 32 d6 88 14 01 8b 4c 24 50 0f b6 06 03 cb 03 44 24 2c 89 4c 24 50 0f b6 09 03 c8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}