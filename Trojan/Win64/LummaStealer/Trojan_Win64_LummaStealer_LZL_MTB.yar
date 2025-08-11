
rule Trojan_Win64_LummaStealer_LZL_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.LZL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 c1 0f b6 c1 0f b6 84 04 ?? ?? ?? ?? 48 63 4c 24 70 48 8b 54 24 28 30 04 0a 8b 5c 24 70 83 c3 01 b8 b8 63 b9 78 3d 67 c8 35 0e 0f 8f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}