
rule Trojan_Win32_LummaStealer_TTV_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.TTV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {f6 e1 89 f1 00 c0 00 c3 89 c8 24 ?? 28 c3 0f b6 c3 01 d0 04 0b 32 04 17 04 c9 88 04 17 42 83 c1 ?? 83 fa 1b 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}