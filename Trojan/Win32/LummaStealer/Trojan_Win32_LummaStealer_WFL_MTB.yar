
rule Trojan_Win32_LummaStealer_WFL_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.WFL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 0c 01 31 c1 81 f1 65 31 c8 04 89 4c 24 04 8b 44 24 04 04 0f 8b 4c 24 ?? 8b 14 24 88 04 11 8b 04 24 83 e8 ff 89 04 24 eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}