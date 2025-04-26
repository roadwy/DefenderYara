
rule Trojan_Win32_LummaStealer_MIP_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.MIP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 0c 24 8b 14 24 0f b6 54 14 28 81 c1 92 ea fe 52 31 d1 89 4c 24 ?? 8b 4c 24 ?? 80 c1 26 8b 14 24 88 4c 14 ?? ff 04 24 8b 0c 24 83 f9 67 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}