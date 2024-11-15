
rule Trojan_Win32_LummaStealer_BKC_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.BKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 f6 ff 0f af f5 89 d3 21 fb 09 fa 0f af d3 01 f2 03 14 24 8a 1c 15 ?? ?? ?? ?? 89 c6 83 c6 ff 88 58 ff 8a 14 15 ?? ?? ?? ?? 83 c6 ff 88 50 fe c1 e9 08 89 f0 eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}