
rule Trojan_Win32_LummaStealer_DFL_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.DFL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 c8 89 44 24 04 8b 44 24 04 34 80 8b 4c 24 ?? 8b 14 24 88 04 11 8b 04 24 83 f0 ff 31 c9 29 c1 89 0c 24 eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}