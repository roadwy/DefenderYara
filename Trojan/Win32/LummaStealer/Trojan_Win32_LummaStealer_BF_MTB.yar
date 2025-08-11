
rule Trojan_Win32_LummaStealer_BF_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 54 24 ?? 83 c0 01 32 11 88 54 24 ?? 0f b6 54 24 ?? 32 91 ?? ?? ?? 00 88 54 24 ?? 0f b6 54 24 ?? 32 91 ?? ?? ?? 00 88 54 24 ?? 8b 54 24 ?? 81 c2 ?? ?? ?? 00 89 54 24 ?? 83 f8 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}