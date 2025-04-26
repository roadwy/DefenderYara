
rule Trojan_Win32_LummaStealer_YYV_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.YYV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 04 83 c0 46 89 04 24 83 2c 24 0a ?? 83 2c 24 ?? 8a 04 24 30 04 32 42 3b d7 7c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}