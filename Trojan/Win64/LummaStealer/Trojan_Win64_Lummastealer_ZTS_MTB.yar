
rule Trojan_Win64_Lummastealer_ZTS_MTB{
	meta:
		description = "Trojan:Win64/Lummastealer.ZTS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 c1 0f b6 c1 0f b6 84 04 ?? ?? ?? ?? 48 63 4c 24 70 48 8b 54 24 28 30 04 0a 8b 44 24 70 8b 44 24 70 8b 44 24 70 8b 44 24 70 b8 1d 32 cf 80 3d a7 a0 44 e5 0f 8f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}