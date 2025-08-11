
rule Trojan_Win32_LummaStealer_PKV_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.PKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c0 0f b6 c9 0f af c8 8a c1 c0 e8 04 32 04 13 32 c1 32 44 24 12 88 04 13 42 8b 44 24 ?? 40 89 54 24 14 89 44 24 28 81 fa 00 60 05 00 0f 82 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}