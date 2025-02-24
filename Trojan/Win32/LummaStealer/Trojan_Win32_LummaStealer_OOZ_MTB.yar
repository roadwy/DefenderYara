
rule Trojan_Win32_LummaStealer_OOZ_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.OOZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {46 0f b6 84 34 18 01 00 00 8b 0c 24 00 c1 89 0c 24 0f b6 c9 0f b6 94 0c 18 01 00 00 88 94 34 18 01 00 00 88 84 0c 18 01 00 00 02 84 34 ?? ?? ?? ?? 0f b6 c0 0f b6 84 04 18 01 00 00 8b 8c 24 ?? ?? ?? ?? 30 04 19 43 3b 9c 24 34 02 00 00 0f 84 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}